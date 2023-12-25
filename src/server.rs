use anyhow::Result;
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpListener;
use tracing::{info, error};

use crate::{config::config, proxy::start_proxy};

pub struct Server {
    // args: Args,
}

impl Server {
    pub fn new() -> Self {
        Self {
			// args
		}
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&config().server_listen).await?;
        info!("server listen on: {}", &config().server_listen);
        loop {
            let (socket, addr) = listener.accept().await?;
            info!("|{:?}| new incoming connection", addr);
            socket.set_nodelay(!config().scramble)?;
            {
                let socket_ref = SockRef::from(&socket);
                let ka = TcpKeepalive::new();
                socket_ref.set_tcp_keepalive(&ka)?;
                socket_ref.set_reuse_address(true)?;
            }

            tokio::spawn(async move {
                match start_proxy(socket).await {
                    Ok(_) => {
                        info!("|{:?}| connection end", addr);
                    },
                    Err(err) => {
						// let _ = socket.shutdown().await;
                        error!("proxy error: {:?}", err);
					},
                }
            });
        }
    }
}
