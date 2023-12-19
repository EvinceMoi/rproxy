use std::mem::MaybeUninit;

use crate::{config::config, proxy::{socks_proxy, http_proxy}};
use anyhow::{bail, Result};
use socket2::SockRef;
use tokio::net::TcpStream;

enum SessionType {
    SOCKS5,
    SOCKS4,
    TLS,
    PlainHTTP,
    Unknown,
}

pub async fn start_session(sock: TcpStream) -> Result<()> {
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


async fn tls_proxy(mut sock: TcpStream) -> Result<()> {
    todo!()
}



