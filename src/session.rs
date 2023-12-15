use std::{
    mem::MaybeUninit,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
};

use crate::{
    config::config,
    socks::{
        auth_negotiation, parse_method_selection, parse_request, reply_method_selection, Address,
        Command, Method, Rep, reply_request,
    }, client::init_upstream,
};
use anyhow::{bail, Result};
use bytes::{BufMut, Bytes, BytesMut};
use socket2::SockRef;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufStream, self},
    net::{TcpSocket, TcpStream, ToSocketAddrs},
};
use tracing::{info, warn, debug};

enum SessionType {
    SOCKS5,
    SOCKS4,
    TLS,
    PlainHTTP,
    Unknown,
}

pub async fn start_session(sock: &mut TcpStream) -> Result<()> {
    let st = proto_detect(&sock).await?;
    match st {
        SessionType::SOCKS5 => socks_proxy(sock).await?,
        SessionType::SOCKS4 => bail!("socks4 not supported"),
        SessionType::TLS => todo!(),
        SessionType::PlainHTTP => {
            if config().disable_http || config().disable_insecure {
                bail!("plain http protocol disabled")
            }
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
    let methods = parse_method_selection(sock).await?;

    let server_method = {
        if !config().auth_users.is_empty() {
            Method::Classic
        } else {
            Method::NoAuth
        }
    };
    let selected = {
        let selected = methods.iter().any(|m| m == &server_method);
        if selected {
            server_method
        } else {
            Method::NoAcceptableMethod
        }
    };
    debug!("selected method: {:?}", selected);
    reply_method_selection(sock, selected).await?;

    if let Method::Classic = selected {
        // do auth
        auth_negotiation(sock, &config().auth_users).await?;
    }

    let (cmd, atyp, address) = parse_request(sock).await?;
    match cmd {
        Command::Connect => {
            let connect = do_connect(address).await
                .map_err(|err| {
                    match err.kind() {
                        ErrorKind::ConnectionRefused => Rep::ConnectionRefused,
                        ErrorKind::HostUnreachable => Rep::HostUnreachable,
                        ErrorKind::NetworkUnreachable => Rep::NetworkUnreachable,
                        ErrorKind::TimedOut => Rep::TTLExpired,
                        _ => Rep::GeneralSocksServerFailure,
                    }
                });
            match connect {
                Ok(mut up) => {
                    let addr = up.peer_addr().unwrap();
                    reply_request(sock, Rep::Succeeded, Some(Address::Socket(addr))).await?;
                    // forward
                    io::copy_bidirectional(sock, &mut up).await?;
                },
                Err(rep) => {
                    reply_request(sock, rep, None).await?;
                    sock.shutdown().await?;
                },
            }
        }
        Command::Bind => {
            bail!("socks request unsupported command")
        }
        Command::UDP => {
            todo!("udp support")
        }
    }

    Ok(())
}

async fn http_proxy(sock: &mut TcpStream) -> Result<()> {
    Ok(())
}

async fn do_connect(addr: Address) -> std::io::Result<TcpStream> {
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
        Some(up) => {
            todo!()
        },
        None => {
            match addr {
                Address::Socket(sa) => {
                    if let Some(sock) = binded_sock {
                        sock.connect(sa).await
                    } else {
                        TcpStream::connect(sa).await
                    }
                }
                Address::Domain(da) => {
                    TcpStream::connect(da).await
                }
            }
        },
    }
}

// impl Drop for Session {
//     fn drop(&mut self) {
//         if let Ok(addr) = self.sock.peer_addr() {
//             info!("connection closed: {:?}", addr);
//         }
//     }
// }
