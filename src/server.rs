use crate::error::ProviderError;
use crate::quote::process_quotes;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Serialize, Deserialize)]
struct QuoteRequest {
    quote: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct QuoteResponse {
    encrypted_key: Vec<u8>,
    provider_quote: Vec<u8>,
}

pub struct Server {
    addr: String,
}

impl Server {
    pub fn new(addr: String) -> Self {
        Self { addr }
    }

    pub async fn run(&self) -> Result<(), ProviderError> {
        let listener = TcpListener::bind(&self.addr).await.map_err(|e| {
            error!("Failed to bind to {}: {}", self.addr, e);
            ProviderError::NetworkError(e.to_string())
        })?;

        info!("Listening on {}", self.addr);

        while let Ok((socket, peer_addr)) = listener.accept().await {
            info!("New connection from: {}", peer_addr);
            
            tokio::spawn(async move {
                if let Err(e) = handle_connection(socket).await {
                    error!("Connection error from {}: {}", peer_addr, e);
                }
            });
        }

        Ok(())
    }
}

async fn handle_connection(mut socket: TcpStream) -> Result<(), ProviderError> {
    // Read request length
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await.map_err(|e| {
        ProviderError::NetworkError(format!("Failed to read request length: {}", e))
    })?;

    let req_len = u32::from_be_bytes(len_buf) as usize;
    debug!("Expecting request of {} bytes", req_len);

    // Read request data
    let mut request_data = vec![0u8; req_len];
    socket.read_exact(&mut request_data).await.map_err(|e| {
        ProviderError::NetworkError(format!("Failed to read request: {}", e))
    })?;

    // Parse request
    let request: QuoteRequest = serde_json::from_slice(&request_data)?;
    debug!("Received quote of {} bytes", request.quote.len());

    // Process quote
    let provider_response = process_quotes(&request.quote).await?;
    
    
    // Prepare response
    let response = QuoteResponse {
        encrypted_key: provider_response.encrypted_key,
        provider_quote: provider_response.provider_quote,
    };

    let response_data = serde_json::to_vec(&response)?;

    // Send response length
    socket
        .write_all(&(response_data.len() as u32).to_be_bytes())
        .await
        .map_err(|e| {
            ProviderError::NetworkError(format!("Failed to send response length: {}", e))
        })?;

    // Send response
    socket.write_all(&response_data).await.map_err(|e| {
        ProviderError::NetworkError(format!("Failed to send response: {}", e))
    })?;

    debug!("Response sent successfully");
    Ok(())
}
