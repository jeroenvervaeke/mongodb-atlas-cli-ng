//! Secret store backend for Linux and Windows, built on the `keyring` crate.
//!
//! Naming follows zalando/go-keyring (used by the official Atlas CLI) so both
//! CLIs read and write the same credentials:
//! - Windows: Credential Manager target `<service>:<account>`.
//!
//! Secrets go through the raw-bytes API: go-keyring stores UTF-8 bytes, while
//! the crate's `set_password` would write UTF-16LE on Windows.

use keyring::Entry;

use crate::secrets::SecretStoreError;

pub fn is_available() -> bool {
    entry("default", "dummy").is_ok()
}

pub fn get(service: &str, account: &str) -> Result<Option<String>, SecretStoreError> {
    match entry(service, account)?.get_secret() {
        Ok(bytes) => String::from_utf8(bytes).map(Some).map_err(|e| {
            SecretStoreError::InvalidKeyStoreFormat {
                reason: format!("secret is not valid UTF-8: {e}"),
            }
        }),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(unavailable(e)),
    }
}

pub fn set(service: &str, account: &str, value: &str) -> Result<(), SecretStoreError> {
    entry(service, account)?
        .set_secret(value.as_bytes())
        .map_err(unavailable)
}

pub fn delete(service: &str, account: &str) -> Result<(), SecretStoreError> {
    match entry(service, account)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(unavailable(e)),
    }
}

fn entry(service: &str, account: &str) -> Result<Entry, SecretStoreError> {
    #[cfg(windows)]
    // keyring-rs defaults to `<account>.<service>`; go-keyring uses `<service>:<account>`.
    let entry = Entry::new_with_target(&format!("{service}:{account}"), service, account);
    #[cfg(not(windows))]
    let entry = Entry::new(service, account);
    entry.map_err(|e| SecretStoreError::InvalidKeyStoreFormat {
        reason: e.to_string(),
    })
}

fn unavailable(e: keyring::Error) -> SecretStoreError {
    SecretStoreError::KeyStoreUnavailable {
        reason: e.to_string(),
    }
}
