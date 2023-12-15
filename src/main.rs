#![feature(io_error_more)]

mod config;
mod server;
mod logging;
mod session;
mod socks;
mod utils;
mod client;


use config::config;
use anyhow::Result;
use server::Server;
use tracing::{info, debug};


#[tokio::main]
async fn main() -> Result<()> {
    if !config().disable_logs {
        logging::setup_tracing()?;
        info!(">> logging setup ok");
    }

    debug!(">> {:?}", config());
    let server = Server::new();
    server.run().await?;

    Ok(())
}
