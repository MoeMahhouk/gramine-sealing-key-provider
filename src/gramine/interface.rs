use crate::error::ProviderError;
use log::{debug, error};
use std::fs;
use std::sync::Mutex;

static ATTESTATION_LOCK: Mutex<()> = Mutex::new(());
// OS error 13; libc name is EACCES (permission denied).
const OS_ERROR_EACCES: i32 = 13;

fn map_attestation_io_error(context: &str, e: std::io::Error) -> ProviderError {
    if e.kind() == std::io::ErrorKind::PermissionDenied
        || e.raw_os_error() == Some(OS_ERROR_EACCES)
    {
        error!(
            "fatal: permission denied {context}: {e}; requires restart"
        );
        ProviderError::RestartRequired {
            context: context.to_string(),
            source: e,
        }
    } else {
        error!("attestation I/O error {context}: {e}");
        ProviderError::IOError(e)
    }
}

pub fn get_sealing_key() -> Result<Vec<u8>, ProviderError> {
    debug!("reading sealing key from Gramine");
    fs::read("/dev/attestation/keys/_sgx_mrenclave")
        .map_err(|e| map_attestation_io_error("reading /dev/attestation/keys/_sgx_mrenclave", e))
}

pub fn set_user_report_data(data: &[u8]) -> Result<(), ProviderError> {
    debug!("setting user report data: {} bytes", data.len());
    if data.len() > 64 {
        return Err(ProviderError::CryptoError(
            "User report data must not exceed 64 bytes".into(),
        ));
    }

    // Pad data to 64 bytes if necessary
    let mut padded_data = vec![0u8; 64];
    padded_data[..data.len()].copy_from_slice(data);

    fs::write("/dev/attestation/user_report_data", &padded_data)
        .map_err(|e| map_attestation_io_error("writing /dev/attestation/user_report_data", e))
}

pub fn get_quote_with_data(user_data: &[u8]) -> Result<Vec<u8>, ProviderError> {
    debug!("setting user report data and getting quote");

    // Serialize /dev/attestation access; Gramine's pseudo-FS is not thread-safe.
    let _guard = ATTESTATION_LOCK.lock().map_err(|_| {
        ProviderError::IOError(std::io::Error::new(
            std::io::ErrorKind::Other,
            "attestation lock poisoned",
        ))
    })?;

    // First set the user report data
    set_user_report_data(user_data)?;

    // Then get the quote
    fs::read("/dev/attestation/quote")
        .map_err(|e| map_attestation_io_error("reading /dev/attestation/quote", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_eacces_to_restart_required() {
        let err = std::io::Error::from_raw_os_error(OS_ERROR_EACCES);
        let result = map_attestation_io_error("test context", err);
        assert!(
            matches!(result, ProviderError::RestartRequired { ref context, .. } if context == "test context"),
            "expected RestartRequired, got: {result:?}"
        );
    }

    #[test]
    fn map_permission_denied_to_restart_required() {
        let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let result = map_attestation_io_error("test perm", err);
        assert!(
            matches!(result, ProviderError::RestartRequired { ref context, .. } if context == "test perm"),
            "expected RestartRequired, got: {result:?}"
        );
    }

    #[test]
    fn map_other_error_to_io_error() {
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let result = map_attestation_io_error("test other", err);
        assert!(
            matches!(result, ProviderError::IOError(_)),
            "expected IOError, got: {result:?}"
        );
    }
}
