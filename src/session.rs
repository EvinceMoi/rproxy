use std::{
    io::ErrorKind,
    mem::MaybeUninit,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
};

use crate::{config::{config, proxy_sn}, utils::ssl_config};
use anyhow::{bail, ensure, Result};
use base64::Engine;
use bytes::Bytes;
use http_body_util::Empty;
use hyper::{
    client::conn::http1,
    upgrade::Upgraded,
};
use hyper_util::rt::TokioIo;
use rustls::pki_types;
use socket2::SockRef;
use socks5_impl::protocol::{
    handshake, password_method::Status, Address, AsyncStreamOperation, AuthMethod, Command, Reply,
    Request, Response,
};
use tokio::{
    io::{ self, AsyncRead, AsyncWrite, AsyncWriteExt },
    net::{TcpSocket, TcpStream},
};
use tokio_rustls::{TlsConnector, TlsStream};
use tracing::{debug, warn};
use url::Url;

enum SessionType {
    SOCKS5,
    SOCKS4,
    TLS,
    PlainHTTP,
    Unknown,
}

enum ProxyError {
    Socks(Reply),
    Http(http::StatusCode),
    UnknownScheme,
}

#[derive(Debug)]
enum ProxyStream {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
    Http((TokioIo<Upgraded>, SocketAddr)),
}

impl ProxyStream {
    pub fn set_nodelay(&mut self, nodelay: bool) -> io::Result<()> {
        match self {
            ProxyStream::Tcp(tcp) => tcp.set_nodelay(nodelay),
            ProxyStream::Tls(tls) => tls.get_mut().0.set_nodelay(nodelay),
            ProxyStream::Http(http) => Ok(()),
        }
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            ProxyStream::Tcp(tcp) => tcp.local_addr(),
            ProxyStream::Tls(tls) => tls.get_ref().0.local_addr(),
            ProxyStream::Http(up) => Ok(up.1.clone()),
        }
    }
}
impl AsyncRead for ProxyStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ProxyStream::Tcp(tcp) => Pin::new(tcp).poll_read(cx, buf),
            ProxyStream::Tls(tls) => Pin::new(tls).poll_read(cx, buf),
            ProxyStream::Http((http, _)) => Pin::new(http).poll_read(cx, buf),
        }
    }
}
impl AsyncWrite for ProxyStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::prelude::v1::Result<usize, std::io::Error>> {
        match self.get_mut() {
            ProxyStream::Tcp(tcp) => Pin::new(tcp).poll_write(cx, buf),
            ProxyStream::Tls(tls) => Pin::new(tls).poll_write(cx, buf),
            ProxyStream::Http((http, _)) => Pin::new(http).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::prelude::v1::Result<(), std::io::Error>> {
        match self.get_mut() {
            ProxyStream::Tcp(tcp) => Pin::new(tcp).poll_flush(cx),
            ProxyStream::Tls(tls) => Pin::new(tls).poll_flush(cx),
            ProxyStream::Http((http, _)) => Pin::new(http).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::prelude::v1::Result<(), std::io::Error>> {
        match self.get_mut() {
            ProxyStream::Tcp(tcp) => Pin::new(tcp).poll_shutdown(cx),
            ProxyStream::Tls(tls) => Pin::new(tls).poll_shutdown(cx),
            ProxyStream::Http((http, _)) => Pin::new(http).poll_shutdown(cx),
        }
    }
}

pub async fn start_session(sock: &mut TcpStream) -> Result<()> {
    let st = proto_detect(&sock).await?;
    match st {
        SessionType::SOCKS5 => socks_proxy(sock).await?,
        SessionType::SOCKS4 => bail!("socks4 not supported"),
        SessionType::TLS => tls_proxy(sock).await?,
        SessionType::PlainHTTP => {
            if config().disable_http || config().disable_insecure {
                bail!("plain http protocol disabled")
            }
            http_proxy(sock).await?;
        }
        SessionType::Unknown => bail!("unsupported protocol"),
    }

    Ok(())
}

async fn proto_detect(sock: &TcpStream) -> Result<SessionType> {
    sock.readable().await?;
    // peek
    let fb = {
        let sock = SockRef::from(&sock);
        let mut buf: [MaybeUninit<u8>; 5] = unsafe { MaybeUninit::uninit().assume_init() };
        let size = sock.peek(&mut buf)?;
        if size.eq(&0) {
            bail!("peek message: no data");
        }

        unsafe { buf[0].assume_init() }
    };

    match fb {
        0x05 => {
            // socks5
            Ok(SessionType::SOCKS5)
        }
        0x04 => {
            // socks4
            Ok(SessionType::SOCKS4)
        }
        0x16 => {
            // http/socks proxy with tls
            Ok(SessionType::TLS)
        }
        0x47 | 0x50 | 0x43 => {
            // plain http protocol
            Ok(SessionType::PlainHTTP)
        }
        _ => Ok(SessionType::Unknown),
    }
}

async fn socks_proxy(sock: &mut TcpStream) -> Result<()> {
    let request = handshake::Request::retrieve_from_async_stream(sock).await?;
    let server_method = {
        if !config().auth_users.is_empty() {
            AuthMethod::UserPass
        } else {
            AuthMethod::NoAuth
        }
    };
    if !request.evaluate_method(server_method) {
        let response = handshake::Response::new(AuthMethod::NoAcceptableMethods);
        response.write_to_async_stream(sock).await?;
        let _ = sock.shutdown().await;
        bail!("no acceptable methods form negotiation");
    } else {
        let response = handshake::Response::new(server_method);
        response.write_to_async_stream(sock).await?;
    }

    if server_method == AuthMethod::UserPass {
        let req = handshake::password_method::Request::retrieve_from_async_stream(sock).await?;
        let auth = format!("{}:{}", req.user_key.username, req.user_key.password);
        let matched = config().auth_users.iter().any(|au| au.eq(&auth));
        let status = if matched {
            Status::Succeeded
        } else {
            Status::Failed
        };
        let res = handshake::password_method::Response::new(status);
        res.write_to_async_stream(sock).await?;
        ensure!(matched, "auth failed");
    }

    let req = Request::retrieve_from_async_stream(sock).await?;
    debug!("socks req: {:?}", req);
    match req.command {
        socks5_impl::protocol::Command::Connect => {
            let connect = socks_do_connect(req.address).await;
            match connect {
                Ok(mut up) => {
                    let _ = up.set_nodelay(true);
                    let addr = up.local_addr().unwrap();
                    debug!("up stream addr: {:?}", addr);
                    let resp = Response::new(Reply::Succeeded, Address::SocketAddress(addr));
                    resp.write_to_async_stream(sock).await?;
                    // forward
                    io::copy_bidirectional(sock, &mut up).await?;
                }
                Err(rep) => {
                    debug!("socks_do_connect error: {:?}", rep);
                    let resp = Response::new(rep, Address::unspecified());
                    resp.write_to_async_stream(sock).await?;
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

async fn http_proxy(sock: &mut TcpStream) -> Result<()> {
    Ok(())
}
async fn tls_proxy(sock: &TcpStream) -> Result<()> {
    todo!()
}

async fn socks_do_connect(addr: Address) -> Result<ProxyStream, Reply> {
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

    match config().proxy_pass.as_ref() {
        Some(up) => connect_proxy_pass(up, &addr)
            .await
            .map_err(|e| Reply::GeneralFailure),
        None => match addr {
            Address::SocketAddress(sa) => {
                if let Some(sock) = binded_sock {
                    sock.connect(sa)
                        .await
                        .map_err(io_error_to_reply)
                        .map(ProxyStream::Tcp)
                } else {
                    TcpStream::connect(sa)
                        .await
                        .map_err(io_error_to_reply)
                        .map(ProxyStream::Tcp)
                }
            }
            Address::DomainAddress(name, port) => TcpStream::connect((name, port))
                .await
                .map_err(io_error_to_reply)
                .map(ProxyStream::Tcp),
        },
    }
}

async fn connect_proxy_pass(url: &Url, target: &Address) -> Result<ProxyStream, ProxyError> {
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
async fn connect_socks5(url: &Url, target: &Address) -> Result<ProxyStream, Reply> {
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
    Ok(ProxyStream::Tcp(proxy))
}

async fn connect_http(url: &Url, target: &Address) -> Result<ProxyStream, http::StatusCode> {
    let host = url.host().unwrap().to_string();
    let port = url.port_or_known_default().unwrap();
    let proxy = if url.scheme().eq("https") {
        let ssl_config = ssl_config().map_err(|_| http::StatusCode::INTERNAL_SERVER_ERROR)?;
        let stream = TcpStream::connect((host.clone(), port))
            .await
            .map_err(|_| http::StatusCode::SERVICE_UNAVAILABLE)?;
        let domain = pki_types::ServerName::try_from(proxy_sn())
            .map_err(|_| http::StatusCode::INTERNAL_SERVER_ERROR)?;
        let connector = TlsConnector::from(Arc::new(ssl_config));
        let s = connector
            .connect(domain, stream)
            .await
            .map_err(|_| http::StatusCode::SERVICE_UNAVAILABLE)?;
        ProxyStream::Tls(TlsStream::Client(s))
    } else {
        let stream = TcpStream::connect((host.clone(), port))
            .await
            .map_err(|_| http::StatusCode::SERVICE_UNAVAILABLE)?;
        ProxyStream::Tcp(stream)
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
            let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(pass);
            req.headers_mut().insert(
                hyper::header::PROXY_AUTHORIZATION,
                format!("Basic {encoded}").parse().unwrap(),
            );
        }
        req
    };
    let (mut sender, conn) = http1::handshake(TokioIo::new(proxy))
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
            Ok(up) => return Ok(ProxyStream::Http((TokioIo::new(up), local_addr))),
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
