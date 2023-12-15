use anyhow::{Result, bail};
use tokio::net::{TcpSocket, TcpStream};
use url::Url;

pub async fn init_upstream(endp: &Url) -> Result<TcpStream> {
	match endp.scheme() {
		"socks5" => {
			// endp
		},
		"http" => todo!(),
		"https" => todo!(),
		unknown => bail!("unknown upstream scheme: {}", unknown)
	}
	todo!()
}

// pub async fn init_socks_upstream(endp: &Url) -> Result<TcpStream> {

// 	TcpStream::connect().await
// }
