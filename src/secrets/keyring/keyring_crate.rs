//! Secret store backend for Linux and Windows, built on the `keyring` crate.
//!
//! Naming follows zalando/go-keyring (used by the official Atlas CLI) so both
//! CLIs read and write the same credentials:
//! - Linux: secret-service items searched by `service` + `username`. go-keyring
//!   writes only those two attributes into the `login` collection; keyring-rs
//!   additionally tags items it creates with `target`/`application`, but falls
//!   back to a `service` + `username`-only search of the default collection (the
//!   `default` alias points at `login` on stock GNOME Keyring / KWallet), so
//!   both sides find and update each other's items in place.
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
        Err(e) => Err(backend_error(e)),
    }
}

pub fn set(service: &str, account: &str, value: &str) -> Result<(), SecretStoreError> {
    entry(service, account)?
        .set_secret(value.as_bytes())
        .map_err(backend_error)
}

pub fn delete(service: &str, account: &str) -> Result<(), SecretStoreError> {
    match entry(service, account)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(backend_error(e)),
    }
}

fn entry(service: &str, account: &str) -> Result<Entry, SecretStoreError> {
    // keyring-rs defaults to `<account>.<service>`; go-keyring uses `<service>:<account>`.
    #[cfg(windows)]
    let entry = Entry::new_with_target(&windows_target_name(service, account), service, account);
    #[cfg(not(windows))]
    let entry = Entry::new(service, account);
    entry.map_err(|e| SecretStoreError::InvalidKeyStoreFormat {
        reason: e.to_string(),
    })
}

// Compiled under `test` on every OS so the go-keyring naming contract is checked in CI everywhere.
#[cfg(any(windows, test))]
fn windows_target_name(service: &str, account: &str) -> String {
    format!("{service}:{account}")
}

fn backend_error(e: keyring::Error) -> SecretStoreError {
    match e {
        // Duplicate items are a store-content problem the user can fix (e.g. in
        // Seahorse / Credential Manager), not an unavailable backend.
        keyring::Error::Ambiguous(matches) => SecretStoreError::InvalidKeyStoreFormat {
            reason: format!(
                "{} keyring items match the same service and account; remove the duplicates",
                matches.len()
            ),
        },
        e => SecretStoreError::KeyStoreUnavailable {
            reason: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_target_name_matches_go_keyring_cred_name() {
        assert_eq!(
            windows_target_name("atlascli_default", "access_token"),
            "atlascli_default:access_token"
        );
    }

    #[test]
    fn test_backend_error_reports_ambiguous_matches_as_store_format_problem() {
        let err = backend_error(keyring::Error::Ambiguous(Vec::new()));
        assert!(
            matches!(err, SecretStoreError::InvalidKeyStoreFormat { reason } if reason.contains("duplicates"))
        );
    }

    #[test]
    fn test_backend_error_reports_other_errors_as_unavailable() {
        let err = backend_error(keyring::Error::NoStorageAccess("locked".into()));
        assert!(matches!(err, SecretStoreError::KeyStoreUnavailable { .. }));
    }
}
