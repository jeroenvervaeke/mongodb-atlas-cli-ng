use std::string::FromUtf8Error;

#[cfg(target_os = "macos")]
use base64::{DecodeError, Engine, prelude::*};
use hex::FromHexError;
use thiserror::Error;

use crate::secrets::SecretStoreError;

#[cfg(target_os = "macos")]
const HEX_ENCODING_PREFIX: &str = "go-keyring-encoded:";
#[cfg(target_os = "macos")]
const BASE64_ENCODING_PREFIX: &str = "go-keyring-base64:";

/// A secret exactly as it sits in the OS keychain: on macOS base64 behind a
/// go-keyring prefix, elsewhere the raw value.
///
/// Only [`encode_password`] produces one and only [`decode_password`] turns
/// it back into a plain `String`, so skipping or doubling either step does
/// not type-check.
#[derive(Clone, PartialEq, Eq)]
pub struct EncodedSecret(pub(crate) String);

impl EncodedSecret {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for EncodedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncodedSecret([redacted])")
    }
}

#[derive(Debug, Error)]
pub enum DecodePasswordError {
    #[error("Invalid hex value: {0}")]
    InvalidHexValue(#[from] FromHexError),
    #[error("Invalid utf8 value: {0}")]
    InvalidUtf8Value(#[from] FromUtf8Error),
    #[cfg(target_os = "macos")]
    #[error("Invalid base64 value: {0}")]
    InvalidBase64Value(#[from] DecodeError),
}

impl From<DecodePasswordError> for SecretStoreError {
    fn from(error: DecodePasswordError) -> Self {
        SecretStoreError::Serialization {
            reason: (error.to_string()),
        }
    }
}

#[cfg(target_os = "macos")]
pub fn decode_password(password: EncodedSecret) -> Result<Option<String>, DecodePasswordError> {
    let password = password.0;
    if let Some(hex_encoded_value) = password.strip_prefix(HEX_ENCODING_PREFIX) {
        let hex = hex::decode(hex_encoded_value)?;
        let decoded = String::from_utf8(hex)?;
        return Ok(none_if_empty(decoded));
    }

    if let Some(base64_encoded_value) = password.strip_prefix(BASE64_ENCODING_PREFIX) {
        let base64 = BASE64_STANDARD.decode(base64_encoded_value)?;
        let decoded = String::from_utf8(base64)?;
        return Ok(none_if_empty(decoded));
    }

    Ok(none_if_empty(password))
}

#[cfg(not(target_os = "macos"))]
pub fn decode_password(password: EncodedSecret) -> Result<Option<String>, DecodePasswordError> {
    Ok(none_if_empty(password.0))
}

fn none_if_empty(password: String) -> Option<String> {
    if password.is_empty() {
        None
    } else {
        Some(password)
    }
}

#[cfg(target_os = "macos")]
pub fn encode_password(password: &str) -> EncodedSecret {
    // We picked base64 as the default encoding because it is what the zalando keyring library uses by default
    let base64 = BASE64_STANDARD.encode(password);
    EncodedSecret(format!("{}{}", BASE64_ENCODING_PREFIX, base64))
}

#[cfg(not(target_os = "macos"))]
pub fn encode_password(password: &str) -> EncodedSecret {
    EncodedSecret(password.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn test_decode_hex_password() {
        let password = EncodedSecret("go-keyring-encoded:616263".to_string());
        let decoded = decode_password(password).unwrap();
        assert_eq!(decoded, Some("abc".to_string()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_decode_base64_password() {
        let password = EncodedSecret("go-keyring-base64:YWJj".to_string());
        let decoded = decode_password(password).unwrap();
        assert_eq!(decoded, Some("abc".to_string()));
    }

    #[test]
    fn test_decode_without_prefix() {
        let password = EncodedSecret("abc".to_string());
        let decoded = decode_password(password).unwrap();
        assert_eq!(decoded, Some("abc".to_string()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_encode_password() {
        let encoded = encode_password("abc");
        assert_eq!(encoded.as_str(), "go-keyring-base64:YWJj");
    }

    #[test]
    fn test_debug_does_not_print_payload() {
        let encoded = encode_password("hunter2");
        assert!(!format!("{encoded:?}").contains("hunter2"));
    }
}
