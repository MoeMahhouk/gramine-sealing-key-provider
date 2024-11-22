mod crypto;
mod error;
mod gramine;
mod quote;
mod server;

use error::ProviderError;
use log::info;
use server::Server;
use std::env;

#[tokio::main]
async fn main() -> Result<(), ProviderError> {
    // Initialize sodium first
    crypto::init_sodium()?;
    
    env_logger::init();
    info!("Starting Gramine Sealing Key Provider");

    #[cfg(feature = "dev-mode")]
    log::warn!("Running in DEVELOPMENT mode - security features are reduced");

    #[cfg(not(feature = "dev-mode"))]
    info!("Running in PRODUCTION mode - full security enabled");

    let addr = env::var("SEALING_PROVIDER_ADDR").unwrap_or_else(|_| "0.0.0.0:3443".to_string());
    
    let server = Server::new(addr);
    server.run().await
}
