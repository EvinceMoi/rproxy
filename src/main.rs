#![feature(io_error_more)]

mod config;
mod logging;
mod proxy;
mod server;
mod utils;

use anyhow::Result;
use config::config;
use server::Server;
use tracing::{debug, info};

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
