use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
};

use anyhow::{bail, ensure, Ok, Result};
use bytes::{BufMut, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub const VERSION: u8 = 0x05;
#[derive(Clone, Copy, PartialEq)]
pub enum Rep {
    Succeeded = 0x00,
    GeneralSocksServerFailure = 0x01,
    ConnectionNotAllowedByRuleset = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TTLExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
    Unassigned = 0x09,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UDP = 0x03,
}

#[derive(Clone, Copy, PartialEq)]
pub enum AddrType {
    IPv4 = 0x01,
    DomainName = 0x03,
    IPv6 = 0x04,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Method {
    NoAuth = 0x00,
    Classic = 0x02, // Username/Password
    NoAcceptableMethod = 0xff,
}

pub enum Address {
    Socket(SocketAddr),
    Domain((String, u16)),
}

async fn read_n(sock: &mut TcpStream, amt: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; amt];
    sock.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn parse_method_selection(sock: &mut TcpStream) -> Result<Vec<Method>> {
    let ver = read_n(sock, 1).await?;
    let ver = ver[0];
    ensure!(ver == VERSION, "bad version number");

    let nmethods = read_n(sock, 1).await?;
    let nmethods = nmethods[0];
    if nmethods == 0 {
        return Ok(vec![Method::NoAcceptableMethod]);
    }

    let methods = {
        let methods = read_n(sock, nmethods as usize).await?;
        methods
            .into_iter()
            .collect::<HashSet<u8>>()
            .into_iter()
            .map(|u| match u {
                0x00 => Method::NoAuth,
                0x02 => Method::Classic,
                _ => Method::NoAcceptableMethod,
            })
            .collect::<Vec<Method>>()
    };
    Ok(methods)
}

pub async fn reply_method_selection(sock: &mut TcpStream, method: Method) -> Result<()> {
    let mut buf = BytesMut::with_capacity(2);
    buf.put_u8(VERSION);
    buf.put_u8(method as u8);
    sock.write_all(&buf).await?;
    ensure!(
        method != Method::NoAcceptableMethod,
        "no acceptable methods from negotiation"
    );
    Ok(())
}

pub async fn auth_negotiation(sock: &mut TcpStream, auth: &Vec<String>) -> Result<()> {
    let d = read_n(sock, 2).await?;
    ensure!(d[0] == 0x01, "negotiation failed, ver error");
    ensure!(d[1] != 0x00, "negotiation failed, invalid ulen");

    let uname = {
        let uname = read_n(sock, d[1] as usize).await?;
        String::from_utf8_lossy(&uname[..]).to_string()
    };

    let plen = read_n(sock, 1).await?;
    ensure!(plen[0] != 0x00, "negotiation failed, invalid plen");
    let passwd = {
        let passwd = read_n(sock, plen[0] as usize).await?;
        String::from_utf8_lossy(&passwd[..]).to_string()
    };

    let to_check = format!("{uname}:{passwd}");
    let matched = auth.iter().any(|au| au.eq(&to_check));
    let status = if matched { 0x00 } else { 0xff };

    let mut buf = BytesMut::with_capacity(2);
    buf.put_u8(0x01);
    buf.put_u8(status);
    sock.write_all(&buf).await?;
    ensure!(matched, "negotiation failed, usrname/passwd mismatch");
    Ok(())
}

pub async fn parse_request(sock: &mut TcpStream) -> Result<(Command, AddrType, Address)> {
    let buf = read_n(sock, 4).await?;
    ensure!(buf[0] == VERSION, "request error: invalid ver");

    let cmd = match buf[1] {
        0x01 => Command::Connect,
        0x02 => Command::Bind,
        0x03 => Command::UDP,
        _ => bail!("request error: invalid cmd"),
    };
    let atyp = match buf[3] {
        0x01 => AddrType::IPv4,
        0x03 => AddrType::DomainName,
        0x04 => AddrType::IPv6,
        _ => bail!("request error: invalid atyp"),
    };

    let remote_addr = match atyp {
        AddrType::IPv4 => {
            let data = read_n(sock, 4 + 2).await?;
            let addr_buf: [u8; 4] = data[..4].try_into().unwrap();
            let addr = IpAddr::from(addr_buf);
            let port = u16::from_be_bytes(data[4..].try_into().unwrap());
            Address::Socket(SocketAddr::from((addr, port)))
        }
        AddrType::DomainName => {
            let len = sock.read_u8().await?;
            let data = read_n(sock, len as usize + 2).await?;
            let addr = String::from_utf8_lossy(&data[0..len as usize]).into_owned();
            let port = u16::from_be_bytes(data[4..].try_into().unwrap());
            Address::Domain((addr, port))
        }
        AddrType::IPv6 => {
            let data = read_n(sock, 16 + 2).await?;
            let addr_buf: [u8; 16] = data[..16].try_into().unwrap();
            let addr = IpAddr::from(addr_buf);
            let port = u16::from_be_bytes(data[16..].try_into().unwrap());
            Address::Socket(SocketAddr::from((addr, port)))
        }
    };
    Ok((cmd, atyp, remote_addr))
}

pub async fn reply_request(sock: &mut TcpStream, rep: Rep, addr: Option<Address>) -> Result<()> {
    let mut buf = BytesMut::with_capacity(10);
    buf.put_u8(VERSION);
    buf.put_u8(rep as u8);
    buf.put_u8(0x00);
    if let Some(addr) = addr {
        match addr {
            Address::Socket(addr) => match addr {
                SocketAddr::V4(addr) => {
                    buf.put_u8(AddrType::IPv4 as u8);
                    addr.ip().octets().into_iter().for_each(|o| {
                        buf.put_u8(o);
                    });
                    buf.put_u16(addr.port());
                }
                SocketAddr::V6(addr) => {
                    buf.put_u8(AddrType::IPv6 as u8);
                    addr.ip().segments().into_iter().for_each(|o| {
                        buf.put_u16(o);
                    });
                    buf.put_u16(addr.port());
                }
            },
            Address::Domain((dn, port)) => {
                buf.put_u8(AddrType::DomainName as u8);
                buf.put_u8(dn.len() as u8);
                buf.put_slice(dn.as_bytes());
                buf.put_u16(port);
            }
        };
    } else {
        buf.put_u8(AddrType::IPv4 as u8);
        buf.put_bytes(0x00, 4);
        buf.put_bytes(0x00, 2);
    }
    sock.write_all(&buf).await?;
    Ok(())
}
