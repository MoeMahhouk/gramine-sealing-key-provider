use crate::crypto::{derive_key, encrypt_key, extract_public_key};
use crate::error::ProviderError;
use crate::gramine::{get_local_quote, get_sealing_key};
use dcap_qvl::{
    collateral::get_collateral_from_pcs,
    quote::{Quote, Report},
    verify::verify,
};
use log::{debug, error, info, warn};
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn process_quotes(tdx_quote_data: &[u8]) -> Result<Vec<u8>, ProviderError> {
    info!("Starting quote processing");
    debug!("Input quote length: {} bytes", tdx_quote_data.len());
    debug!("Input quote (hex): {}", hex::encode(tdx_quote_data));

    // 1. Verify TDX quote
    #[cfg(feature = "dev-mode")]
    {
        warn!("Development mode enabled");
        warn!("Skipping quote verification in dev mode");
    }

    #[cfg(not(feature = "dev-mode"))]
    {
        info!("Production mode - performing full quote verification");
        verify_quote(tdx_quote_data).await?;
    }

    // 2. Parse quotes
    let tdx_quote = parse_quote(tdx_quote_data.to_vec())?;
    let sgx_quote_data = get_local_quote()?;
    let sgx_quote = parse_quote(sgx_quote_data)?;

    // 3. Verify PPID match
    verify_ppid_match(&sgx_quote.quote, &tdx_quote.quote)?;

    // 4. Get measurements and derive key
    let sealing_key = get_sealing_key()?;
    let measurements = extract_measurements(&tdx_quote.quote)?;
    let derived_key = derive_key(&sealing_key, &measurements);

    // 5. Extract public key and encrypt response
    let report_data = get_report_data(&tdx_quote.quote)?;
    let public_key = extract_public_key(report_data)?;
    let encrypted_key = encrypt_key(&derived_key, &public_key)?;

    info!("Successfully processed quote and encrypted response");
    Ok(encrypted_key)
}

fn parse_quote(data: Vec<u8>) -> Result<QuoteData, ProviderError> {
    let quote = Quote::parse(&data)
        .map_err(|_| ProviderError::QuoteParseError("Failed to parse quote".into()))?;

    Ok(QuoteData { quote })
}

#[cfg(not(feature = "dev-mode"))]
async fn verify_quote(quote_data: &[u8]) -> Result<(), ProviderError> {
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

    debug!("SGX PPID: {}", hex::encode(sgx_ppid));
    debug!("TDX PPID: {}", hex::encode(tdx_ppid));

    #[cfg(feature = "dev-mode")]
    {
        warn!("Development mode: Skipping strict PPID verification");
        return Ok(());
    }

    if sgx_ppid != tdx_ppid {
        error!("PPID mismatch between SGX and TDX quotes");
        return Err(ProviderError::PPIDMismatch);
    }

    info!("PPID match confirmed");
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