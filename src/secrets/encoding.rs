#[cfg(target_os = "macos")]
use std::borrow::Cow;
use std::string::FromUtf8Error;

use base64::{DecodeError, Engine, prelude::*};
use hex::FromHexError;
use thiserror::Error;

use crate::secrets::SecretStoreError;

const HEX_ENCODING_PREFIX: &str = "go-keyring-encoded:";
const BASE64_ENCODING_PREFIX: &str = "go-keyring-base64:";

#[derive(Debug, Error)]
pub enum DecodePasswordError {
    #[error("Invalid hex value: {0}")]
    InvalidHexValue(#[from] FromHexError),
    #[error("Invalid utf8 value: {0}")]
    InvalidUtf8Value(#[from] FromUtf8Error),
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
pub fn decode_password(password: String) -> Result<Option<String>, DecodePasswordError> {
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
pub fn decode_password(password: String) -> Result<Option<String>, DecodePasswordError> {
    Ok(none_if_empty(password))
}

fn none_if_empty(password: String) -> Option<String> {
    if password.is_empty() {
        None
    } else {
        Some(password)
    }
}

#[cfg(target_os = "macos")]
pub fn encode_password<'a>(password: &'a str) -> Cow<'a, str> {
    // We picked base64 as the default encoding because it is what the zalando keyring library uses by default
    let base64 = BASE64_STANDARD.encode(password);
    Cow::Owned(format!("{}{}", BASE64_ENCODING_PREFIX, base64))
}

#[cfg(not(target_os = "macos"))]
pub fn encode_password<'a>(password: &'a str) -> Cow<'a, str> {
    Cow::Borrowed(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex_password() {
        let password = "go-keyring-encoded:616263";
        let decoded = decode_password(password.to_string()).unwrap();
        assert_eq!(decoded, Some("abc".to_string()));
    }

    #[test]
    fn test_decode_base64_password() {
        let password = "go-keyring-base64:YWJj";
        let decoded = decode_password(password.to_string()).unwrap();
        assert_eq!(decoded, Some("abc".to_string()));
    }

    #[test]
    fn test_decode_without_prefix() {
        let password = "abc";
        let decoded = decode_password(password.to_string()).unwrap();
        assert_eq!(decoded, Some("abc".to_string()));
    }

    #[test]
    fn test_encode_password() {
        let password = "abc";
        let encoded = encode_password(password);
        assert_eq!(encoded, "go-keyring-base64:YWJj");
    }
}
