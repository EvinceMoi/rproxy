use anyhow::Result;
use socket2::{SockRef, TcpKeepalive};
use tokio::{net::{TcpListener, TcpStream}, io::AsyncWriteExt};
use tracing::{debug, info};

use crate::{config::config, session::start_session};

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
        debug!("prepare to listen on: {}", &config().server_listen);
        let listener = TcpListener::bind(&config().server_listen).await?;
        loop {
            let (mut socket, addr) = listener.accept().await?;
            info!("new incoming connection: {:?}", addr);
            socket.set_nodelay(!config().scramble)?;
            {
                let socket_ref = SockRef::from(&socket);
                let ka = TcpKeepalive::new();
                socket_ref.set_tcp_keepalive(&ka)?;
                socket_ref.set_reuse_address(true)?;
            }

            tokio::spawn(async move {
                // let mut sess = Session::new(socket);
                // let _ = sess.start().await;
                match start_session(&mut socket).await {
                    Ok(_) => {},
                    Err(_) => {
						let _ = socket.shutdown().await;
					},
                }
            });
        }
    }
}
