use std::{io::ErrorKind, net::SocketAddr, pin::Pin, sync::Arc};

use crate::{
    config::config,
    utils::{base64_decode, base64_encode, ssl_config_client, ssl_config_server},
};
use anyhow::{anyhow, bail, ensure, Result};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    client::conn::http1 as client_http1, server::conn::http1 as server_http1, service::service_fn,
    upgrade::Upgraded,
};
use hyper_util::rt::TokioIo;
use rustls::pki_types;
use socks5_impl::protocol::{
    handshake, password_method::Status, Address, AsyncStreamOperation, AuthMethod, Command, Reply,
    Request, Response,
};
use tokio::{
    io::{self, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufStream},
    net::{TcpSocket, TcpStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use tracing::{debug, warn};
use url::Url;

#[derive(Debug)]
pub enum ProxyType {
    SOCKS5,
    SOCKS4,
    TLS,
    PlainHTTP,
    Unknown,
}

fn parse_proxy_type(fb: u8) -> ProxyType {
    match fb {
        0x05 => {
            // socks5
            ProxyType::SOCKS5
        }
        0x04 => {
            // socks4
            ProxyType::SOCKS4
        }
        0x16 => {
            // http/socks proxy with tls
            ProxyType::TLS
        }
        0x47 | 0x50 | 0x43 => {
            // plain http protocol
            ProxyType::PlainHTTP
        }
        _ => ProxyType::Unknown,
    }
}

pub async fn proto_detect(stream: &TcpStream) -> Result<ProxyType> {
    let fb = {
        stream.readable().await?;
        let mut buf = vec![0u8; 1];
        let size = stream.peek(&mut buf).await?;
        if size.eq(&0) {
            bail!("peek failed: no data")
        }
        buf[0]
    };
    Ok(parse_proxy_type(fb))
}

pub async fn start_proxy(mut sock: TcpStream) -> Result<()> {
    let pt = proto_detect(&mut sock).await?;
    handle_type(pt, sock).await?;

    Ok(())
}
async fn handle_type(pt: ProxyType, income: TcpStream) -> Result<()> {
    match pt {
        ProxyType::SOCKS5 => socks_proxy(income).await?,
        ProxyType::SOCKS4 => bail!("socks4 not supported"),
        ProxyType::TLS => {
            tls_proxy(income).await?;
        }
        ProxyType::PlainHTTP => {
            if config().disable_http || config().disable_insecure {
                bail!("plain http protocol disabled");
            }
            http_proxy(income).await?
        }
        ProxyType::Unknown => bail!("unsupported protocol"),
    }

    Ok(())
}

#[derive(Debug)]
pub enum ProxyError {
    Socks(Reply),
    Http(http::StatusCode),
    UnknownScheme,
}

#[derive(Debug)]
pub enum BaseStream {
    Tcp(BufStream<TcpStream>),
    Tls(BufStream<TlsStream<TcpStream>>),
    Http((TokioIo<Upgraded>, SocketAddr)),
}

impl BaseStream {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            BaseStream::Tcp(tcp) => tcp.get_ref().local_addr(),
            BaseStream::Tls(tls) => tls.get_ref().get_ref().0.local_addr(),
            BaseStream::Http(up) => io::Result::Ok(up.1.clone()),
        }
    }
    #[allow(dead_code)]
    pub fn lowest_layer(&self) -> &TcpStream {
        match self {
            BaseStream::Tcp(tcp) => tcp.get_ref(),
            BaseStream::Tls(tls) => tls.get_ref().get_ref().0,
            BaseStream::Http(_up) => todo!(),
        }
    }
}
impl AsyncRead for BaseStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            BaseStream::Tcp(tcp) => Pin::new(tcp).poll_read(cx, buf),
            BaseStream::Tls(tls) => Pin::new(tls).poll_read(cx, buf),
            BaseStream::Http((http, _)) => Pin::new(http).poll_read(cx, buf),
        }
    }
}
impl AsyncWrite for BaseStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::prelude::v1::Result<usize, std::io::Error>> {
        match self.get_mut() {
            BaseStream::Tcp(tcp) => Pin::new(tcp).poll_write(cx, buf),
            BaseStream::Tls(tls) => Pin::new(tls).poll_write(cx, buf),
            BaseStream::Http((http, _)) => Pin::new(http).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::prelude::v1::Result<(), std::io::Error>> {
        match self.get_mut() {
            BaseStream::Tcp(tcp) => Pin::new(tcp).poll_flush(cx),
            BaseStream::Tls(tls) => Pin::new(tls).poll_flush(cx),
            BaseStream::Http((http, _)) => Pin::new(http).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::prelude::v1::Result<(), std::io::Error>> {
        match self.get_mut() {
            BaseStream::Tcp(tcp) => Pin::new(tcp).poll_shutdown(cx),
            BaseStream::Tls(tls) => Pin::new(tls).poll_shutdown(cx),
            BaseStream::Http((http, _)) => Pin::new(http).poll_shutdown(cx),
        }
    }
}

pub async fn socks_proxy<S>(mut sock: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let request = handshake::Request::retrieve_from_async_stream(&mut sock).await?;
    let server_method = {
        if !config().auth_users.is_empty() {
            AuthMethod::UserPass
        } else {
            AuthMethod::NoAuth
        }
    };
    if !request.evaluate_method(server_method) {
        let response = handshake::Response::new(AuthMethod::NoAcceptableMethods);
        response.write_to_async_stream(&mut sock).await?;
        sock.flush().await?;
        let _ = sock.shutdown().await;
        bail!("no acceptable methods form negotiation");
    } else {
        let response = handshake::Response::new(server_method);
        response.write_to_async_stream(&mut sock).await?;
        sock.flush().await?;
    }

    if server_method == AuthMethod::UserPass {
        let req =
            handshake::password_method::Request::retrieve_from_async_stream(&mut sock).await?;
        let auth = format!("{}:{}", req.user_key.username, req.user_key.password);
        let matched = config().auth_users.iter().any(|au| au.eq(&auth));
        let status = if matched {
            Status::Succeeded
        } else {
            Status::Failed
        };
        let res = handshake::password_method::Response::new(status);
        res.write_to_async_stream(&mut sock).await?;
        sock.flush().await?;
        ensure!(matched, "auth failed");
    }

    let req = Request::retrieve_from_async_stream(&mut sock).await?;
    match req.command {
        socks5_impl::protocol::Command::Connect => {
            let connect = do_connect(req.address).await;
            match connect {
                Ok(mut up) => {
                    let addr = up.local_addr().unwrap();
                    debug!("up stream addr: {:?}", addr);
                    let resp = Response::new(Reply::Succeeded, Address::SocketAddress(addr));
                    resp.write_to_async_stream(&mut sock).await?;
                    sock.flush().await?;
                    // forward
                    io::copy_bidirectional(&mut sock, &mut up).await?;
                }
                Err(rep) => {
                    debug!("socks_do_connect error: {:?}", rep);
                    let reply = match rep {
                        ProxyError::Socks(reply) => reply,
                        _ => Reply::GeneralFailure,
                    };
                    let resp = Response::new(reply, Address::unspecified());
                    resp.write_to_async_stream(&mut sock).await?;
                    sock.flush().await?;
                    sock.shutdown().await?;
                }
            }
        }
        socks5_impl::protocol::Command::Bind => {
            bail!("socks request unsupported command");
        }
        socks5_impl::protocol::Command::UdpAssociate => todo!("udp support"),
    }

    Ok(())
}

async fn do_connect(addr: Address) -> Result<BaseStream, ProxyError> {
    match config().proxy_pass.as_ref() {
        Some(up) => connect_proxy_pass(up, &addr).await,
        None => connect_target(&addr)
            .await
            .map_err(io_error_to_reply)
            .map_err(|e| ProxyError::Socks(e)),
    }
}

pub async fn http_proxy<S>(sock: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(sock);
    server_http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service_fn(http_proxy_server_callback))
        .with_upgrades()
        .await
        .map_err(|e| anyhow!(e))
}

// taken from hyper http_proxy example
async fn http_proxy_server_callback(
    req: hyper::Request<hyper::body::Incoming>,
) -> Result<hyper::Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    if req.method() == hyper::Method::CONNECT {
        if !config().auth_users.is_empty() {
            let ok = req
                .headers()
                .get(hyper::header::PROXY_AUTHORIZATION)
                .map(|v| {
                    v.to_str()
                        .map(|s| {
                            debug!("auth: {s}");
                            let pauth = s.split(' ').collect::<Vec<&str>>();
                            if pauth.len() != 2 {
                                return String::new();
                            }
                            if !pauth[0].to_lowercase().eq("basic") {
                                return String::new();
                            }
                            let auth = {
                                let auth = base64_decode(pauth[1])
                                    .map(|dat| String::from_utf8_lossy(&dat).to_string());
                                if auth.is_none() {
                                    return String::new();
                                }
                                auth.unwrap()
                            };
                            debug!("auth decoded: {auth}");
                            return auth;
                        })
                        .map(|s| {
                            if s.is_empty() {
                                false
                            } else {
                                config().auth_users.iter().any(|au| au.eq(&s))
                            }
                        })
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if !ok {
                let mut resp = hyper::Response::new(
                    Full::new("Proxy Authentication Required".into())
                        .map_err(|never| match never {})
                        .boxed(),
                );
                *resp.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
                return Ok(resp);
            }
        }
        let host = req.uri().host().as_ref().unwrap().to_string();
        let port = req.uri().port_u16().unwrap();
        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(up) => {
                    let mut from = TokioIo::new(up);
                    let to = do_connect(Address::DomainAddress(host.clone(), port)).await;
                    match to {
                        Ok(mut to) => {
                            let _ = io::copy_bidirectional(&mut from, &mut to).await;
                        }
                        Err(_err) => {}
                    }
                }
                Err(_e) => {}
            }
        });
        Ok(hyper::Response::new(
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        ))
    } else {
        // unsupported method, pretend to be a normal web server
        let resp = hyper::Response::new(
            Full::new("hello php".into())
                .map_err(|never| match never {})
                .boxed(),
        );
        Ok(resp)
    }
}

pub async fn tls_proxy(sock: TcpStream) -> Result<()> {
    let config = ssl_config_server()?;
    let accpetor = TlsAcceptor::from(Arc::new(config));

    let stream = accpetor.accept(sock).await?;
    let mut bs = BufStream::new(stream);
    let fb = {
        let buf = bs.fill_buf().await?;
        ensure!(buf.len() > 0, "tls_proxy eof");
        buf[0]
    };

    match parse_proxy_type(fb) {
        ProxyType::SOCKS5 => socks_proxy(bs).await?,
        ProxyType::PlainHTTP => http_proxy(bs).await?,
        _ => {
            bail!("unknown protocol after tls handshake");
        }
    }

    Ok(())
}

async fn connect_target(target: &Address) -> Result<BaseStream, io::Error> {
    let bind_local: Option<SocketAddr> =
        config().local_ip.as_ref().map(|l| l.parse().ok()).flatten();
    let binded_sock = bind_local
        .map(|sa| {
            if sa.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            }
        })
        .map(Result::ok)
        .flatten()
        .map(|sock| {
            let _ = sock.set_reuseaddr(true);
            let _ = sock.set_reuseport(true);
            let _ = sock.bind(bind_local.unwrap());
            sock
        });
    match target {
        Address::SocketAddress(sa) => {
            if let Some(sock) = binded_sock {
                sock.connect(sa.clone())
                    .await
                    .map(BufStream::new)
                    .map(BaseStream::Tcp)
            } else {
                TcpStream::connect(sa)
                    .await
                    .map(BufStream::new)
                    .map(BaseStream::Tcp)
            }
        }
        Address::DomainAddress(name, port) => TcpStream::connect((name.clone(), port.clone()))
            .await
            .map(BufStream::new)
            .map(BaseStream::Tcp),
    }
}

async fn connect_proxy_pass(url: &Url, target: &Address) -> Result<BaseStream, ProxyError> {
    match url.scheme() {
        "socks5" => connect_socks5(url, target)
            .await
            .map_err(|r| ProxyError::Socks(r)),
        "https" | "http" => connect_http(url, target)
            .await
            .map_err(|r| ProxyError::Http(r)),
        _ => return Err(ProxyError::UnknownScheme),
    }
}

async fn connect_socks5(url: &Url, target: &Address) -> Result<BaseStream, Reply> {
    let host = url.host().unwrap().to_string();
    let port = url.port_or_known_default().unwrap();
    let mut proxy = TcpStream::connect((host, port))
        .await
        .map_err(io_error_to_reply)?;
    {
        // negotiation
        let has_auth = !url.username().is_empty();
        let method = if has_auth {
            vec![AuthMethod::UserPass]
        } else {
            vec![AuthMethod::NoAuth]
        };
        let req = handshake::Request::new(method);
        req.write_to_async_stream(&mut proxy)
            .await
            .map_err(io_error_to_reply)?;
        let res = handshake::Response::retrieve_from_async_stream(&mut proxy)
            .await
            .map_err(io_error_to_reply)?;
        match res.method {
            AuthMethod::NoAuth => {}
            AuthMethod::UserPass => {
                let usrname = url.username();
                let passwd = url.password().unwrap_or_default();
                let req = handshake::password_method::Request::new(usrname, passwd);
                req.write_to_async_stream(&mut proxy)
                    .await
                    .map_err(io_error_to_reply)?;
                let res =
                    handshake::password_method::Response::retrieve_from_async_stream(&mut proxy)
                        .await
                        .map_err(io_error_to_reply)?;
                if res.status != Status::Succeeded {
                    return Err(Reply::GeneralFailure);
                }
            }
            AuthMethod::NoAcceptableMethods => return Err(Reply::GeneralFailure),
            _ => {}
        }
    }
    {
        // request
        let req = Request::new(Command::Connect, target.clone());
        req.write_to_async_stream(&mut proxy)
            .await
            .map_err(io_error_to_reply)?;
        let res = Response::retrieve_from_async_stream(&mut proxy)
            .await
            .map_err(io_error_to_reply)?;
        if res.reply != Reply::Succeeded {
            return Err(res.reply);
        }
    }
    Ok(BaseStream::Tcp(BufStream::new(proxy)))
}

async fn connect_http(url: &Url, target: &Address) -> Result<BaseStream, http::StatusCode> {
    let host = url.host().unwrap().to_string();
    let port = url.port_or_known_default().unwrap();
    let proxy = if url.scheme().eq("https") {
        let ssl_config =
            ssl_config_client().map_err(|_| http::StatusCode::INTERNAL_SERVER_ERROR)?;
        let stream = TcpStream::connect((host.clone(), port))
            .await
            .map_err(|_| http::StatusCode::SERVICE_UNAVAILABLE)?;
        let domain = pki_types::ServerName::try_from(host)
            .map_err(|_| http::StatusCode::INTERNAL_SERVER_ERROR)?;
        let connector = TlsConnector::from(Arc::new(ssl_config));
        let s = connector
            .connect(domain, stream)
            .await
            .map_err(|_| http::StatusCode::SERVICE_UNAVAILABLE)?;
        BaseStream::Tls(BufStream::new(TlsStream::Client(s)))
    } else {
        let stream = TcpStream::connect((host.clone(), port))
            .await
            .map_err(|_| http::StatusCode::SERVICE_UNAVAILABLE)?;
        BaseStream::Tcp(BufStream::new(stream))
    };
    let local_addr = proxy.local_addr().unwrap();
    // send CONNECT method
    let req = {
        let mut req = hyper::Request::builder()
            .method(hyper::Method::CONNECT)
            .uri(target.to_string())
            .header(hyper::header::HOST, target.to_string())
            .header("Proxy-Connection", "Keep-Alive")
            .header(hyper::header::USER_AGENT, "curl/8.5.0")
            .body(Empty::<Bytes>::new())
            .map_err(|_| http::StatusCode::INTERNAL_SERVER_ERROR)?;
        if !url.username().is_empty() {
            let uname = url.username();
            let passwd = url.password().unwrap_or_default();
            let pass = format!("{uname}:{passwd}");
            let encoded = base64_encode(&pass);
            req.headers_mut().insert(
                hyper::header::PROXY_AUTHORIZATION,
                format!("Basic {encoded}").parse().unwrap(),
            );
        }
        req
    };
    let (mut sender, conn) = client_http1::handshake(TokioIo::new(proxy))
        .await
        .map_err(|_| http::StatusCode::SERVICE_UNAVAILABLE)?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            warn!("connection failed: {:?}", err);
        }
    });
    let res = sender
        .send_request(req)
        .await
        .map_err(|_| http::StatusCode::SERVICE_UNAVAILABLE)?;
    if res.status().is_success() {
        match hyper::upgrade::on(res).await {
            Ok(up) => return Ok(BaseStream::Http((TokioIo::new(up), local_addr))),
            Err(_) => return Err(http::StatusCode::SERVICE_UNAVAILABLE),
        }
    } else {
        return Err(http::StatusCode::SERVICE_UNAVAILABLE);
    }
}

fn io_error_to_reply(err: io::Error) -> Reply {
    match err.kind() {
        ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
        ErrorKind::HostUnreachable => Reply::HostUnreachable,
        ErrorKind::NetworkUnreachable => Reply::NetworkUnreachable,
        ErrorKind::TimedOut => Reply::TtlExpired,
        _ => Reply::GeneralFailure,
    }
}
