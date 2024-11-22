use crate::crypto::{derive_key, encrypt_key, extract_public_key};
use crate::error::ProviderError;
use crate::gramine::{get_quote_with_data, get_sealing_key};
use dcap_qvl::{
    collateral::get_collateral_from_pcs,
    quote::{Quote, Report},
    verify::verify,
};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProviderResponse {
    pub encrypted_key: Vec<u8>,
    pub provider_quote: Vec<u8>,
}

pub async fn process_quotes(tdx_quote_data: &[u8]) -> Result<ProviderResponse, ProviderError> {
    info!("Starting quote processing");
    debug!("Input quote length: {} bytes", tdx_quote_data.len());
    debug!("Input quote (hex): {}", hex::encode(tdx_quote_data));

    // 1. Verify TDX quote
    verify_quote(tdx_quote_data).await?;

    // 2. Parse TDX quote early
    let tdx_quote = parse_quote(tdx_quote_data.to_vec())?;

    // 3. Get initial provider quote (without encrypted key)
    info!("Getting initial provider quote for PPID verification");
    let initial_provider_quote = get_quote_with_data(&[])?; // Empty user data
    let provider_quote_parsed = parse_quote(initial_provider_quote)?;

    // 4. Early PPID verification
    info!("Performing early PPID verification");
    verify_ppid_match(&provider_quote_parsed.quote, &tdx_quote.quote)?;

    // 5. Only proceed with expensive operations after PPID match
    let sealing_key = get_sealing_key()?;
    let measurements = extract_measurements(&tdx_quote.quote)?;
    let derived_key = derive_key(&sealing_key, &measurements);

    // 6. Extract public key and encrypt derived key
    let report_data = get_report_data(&tdx_quote.quote)?;
    let public_key = extract_public_key(report_data)?;
    let encrypted_key = encrypt_key(&derived_key, &public_key)?;

    // Calculate hash of encrypted key
    let hash = calculate_hash(&encrypted_key);

    // 7. Get final quote with hash in user report data
    debug!("Getting final quote with hash in report data");
    let final_provider_quote = get_quote_with_data(&hash)?;

    info!("Successfully processed quote and generated response");
    debug!(
        "Final provider quote length: {} bytes",
        final_provider_quote.len()
    );

    Ok(ProviderResponse {
        encrypted_key,
        provider_quote: final_provider_quote,
    })
}

fn calculate_hash(encrypted_key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(encrypted_key);
    let hash = hasher.finalize();

    // Create 64-byte user report data
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&hash);

    debug!("Hash of encrypted key: {}", hex::encode(&hash));
    report_data.to_vec()
}

fn parse_quote(data: Vec<u8>) -> Result<QuoteData, ProviderError> {
    let quote = Quote::parse(&data)
        .map_err(|_| ProviderError::QuoteParseError("Failed to parse quote".into()))?;

    Ok(QuoteData { quote })
}

async fn verify_quote(quote_data: &[u8]) -> Result<(), ProviderError> {
    #[cfg(feature = "dev-mode")]
    {
        warn!("Skipping quote verification in dev mode");
        return Ok(());
    }

    debug!("Verifying quote with DCAP");

    let collateral = get_collateral_from_pcs(quote_data, std::time::Duration::from_secs(10))
        .await
        .map_err(|_| ProviderError::QuoteVerificationError)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    verify(quote_data, &collateral, now).map_err(|_| ProviderError::QuoteVerificationError)?;

    info!("Quote verified successfully");
    Ok(())
}

#[derive(Debug)]
struct QuoteData {
    quote: Quote,
}

fn verify_ppid_match(sgx_quote: &Quote, tdx_quote: &Quote) -> Result<(), ProviderError> {
    let sgx_ppid = &sgx_quote.header.user_data[..16];
    let tdx_ppid = &tdx_quote.header.user_data[..16];

    info!("Performing PPID verification");
    debug!("SGX Quote Header: {:?}", sgx_quote.header);
    debug!("TDX Quote Header: {:?}", tdx_quote.header);
    debug!("SGX PPID (hex): {}", hex::encode(sgx_ppid));
    debug!("TDX PPID (hex): {}", hex::encode(tdx_ppid));

    #[cfg(feature = "dev-mode")]
    {
        warn!("Development mode: Skipping strict PPID verification");
        return Ok(());
    }

    if sgx_ppid != tdx_ppid {
        error!("PPID mismatch between SGX and TDX quotes");
        error!("SGX PPID: {}", hex::encode(sgx_ppid));
        error!("TDX PPID: {}", hex::encode(tdx_ppid));
        return Err(ProviderError::PPIDMismatch);
    }

    info!("PPID match confirmed, proceeding with key derivation");
    Ok(())
}

fn extract_measurements(quote: &Quote) -> Result<Vec<u8>, ProviderError> {
    let mut measurements = Vec::new();

    match &quote.report {
        Report::TD10(report) => {
            debug!("Processing TD10 measurements");
            measurements.extend_from_slice(&report.mr_td);
            measurements.extend_from_slice(&report.rt_mr0);
            measurements.extend_from_slice(&report.rt_mr1);
            measurements.extend_from_slice(&report.rt_mr2);
            measurements.extend_from_slice(&report.rt_mr3);
        }
        Report::TD15(report) => {
            debug!("Processing TD15 measurements");
            measurements.extend_from_slice(&report.base.mr_td);
            measurements.extend_from_slice(&report.base.rt_mr0);
            measurements.extend_from_slice(&report.base.rt_mr1);
            measurements.extend_from_slice(&report.base.rt_mr2);
            measurements.extend_from_slice(&report.base.rt_mr3);
        }
        _ => {
            error!("Invalid report type for measurements");
            return Err(ProviderError::QuoteParseError("Not a TDX quote".into()));
        }
    }

    debug!("Extracted measurements: {} bytes", measurements.len());
    Ok(measurements)
}

fn get_report_data(quote: &Quote) -> Result<&[u8], ProviderError> {
    match &quote.report {
        Report::TD10(report) => Ok(&report.report_data),
        Report::TD15(report) => Ok(&report.base.report_data),
        _ => Err(ProviderError::QuoteParseError("Not a TDX quote".into())),
    }
}
