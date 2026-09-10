//! Secret store backend for Linux and Windows, built on the `keyring` crate.

use keyring::Entry;

use crate::secrets::SecretStoreError;

pub fn is_available() -> bool {
    entry("default", "dummy").is_ok()
}

pub fn get(service: &str, account: &str) -> Result<Option<String>, SecretStoreError> {
    match entry(service, account)?.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(unavailable(e)),
    }
}

pub fn set(service: &str, account: &str, value: &str) -> Result<(), SecretStoreError> {
    entry(service, account)?
        .set_password(value)
        .map_err(unavailable)
}

pub fn delete(service: &str, account: &str) -> Result<(), SecretStoreError> {
    match entry(service, account)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(unavailable(e)),
    }
}

fn entry(service: &str, account: &str) -> Result<Entry, SecretStoreError> {
    Entry::new(service, account).map_err(|e| SecretStoreError::InvalidKeyStoreFormat {
        reason: e.to_string(),
    })
}

fn unavailable(e: keyring::Error) -> SecretStoreError {
    SecretStoreError::KeyStoreUnavailable {
        reason: e.to_string(),
    }
}
