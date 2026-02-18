//! Error types for the authentication middleware.
//!
//! The main error type [`AuthError`] is generic over `E`, which represents the
//! inner service's error type. This follows the standard Tower pattern where
//! middleware wraps the inner service's error type, allowing callers to handle
//! errors from either the middleware or the underlying HTTP client.

use std::fmt;

use crate::secrets::SecretStoreError;

/// Errors that can occur during the authentication process.
///
/// This enum is generic over `E` — the error type of the inner
/// Tower [`Service`](tower::Service). This design preserves type information
/// from the wrapped HTTP client while also surfacing middleware-specific errors.
///
/// # Why generic?
///
/// Tower services can have any error type (there are no trait bounds on
/// `Service::Error`). By parameterizing `AuthError` over the inner error type,
/// callers can pattern-match on both middleware errors and transport errors
/// without losing type information or boxing.
///
/// # Example
///
/// ```rust,ignore
/// match error {
///     AuthError::Inner(e) => {
///         // Handle HTTP client errors (timeouts, connection refused, etc.)
///     }
///     AuthError::TokenAcquisitionFailed(msg) => {
///         // Handle OAuth2 token refresh failures
///     }
///     _ => { /* ... */ }
/// }
/// ```
#[derive(Debug)]
pub enum AuthError<E> {
    /// An error originating from the inner HTTP service.
    ///
    /// This variant wraps errors like connection failures, timeouts,
    /// or any other transport-level errors from the underlying client.
    Inner(E),

    /// Failed to acquire or refresh an OAuth2 access token.
    ///
    /// This can happen when:
    /// - The token endpoint is unreachable
    /// - The refresh token is invalid or expired
    /// - The client credentials are incorrect
    /// - The token response is malformed
    TokenAcquisitionFailed(String),

    /// Failed to perform HTTP Digest authentication.
    ///
    /// This can happen when:
    /// - The server's `WWW-Authenticate` header is malformed
    /// - The digest algorithm is unsupported
    /// - The authorization header couldn't be constructed
    DigestAuthFailed(String),

    /// Failed to persist a refreshed token to the secret store.
    SecretStoreError(SecretStoreError),
}

// We implement Display manually instead of using thiserror because
// thiserror's derive macro requires `E: Display` at the type level,
// but Tower services don't guarantee Display on their error types.
// By implementing manually, we only require E: Display where Display
// is actually used (in the impl block), not on the struct definition.
impl<E: fmt::Display> fmt::Display for AuthError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Inner(e) => write!(f, "inner service error: {e}"),
            AuthError::TokenAcquisitionFailed(msg) => {
                write!(f, "token acquisition failed: {msg}")
            }
            AuthError::DigestAuthFailed(msg) => {
                write!(f, "digest authentication failed: {msg}")
            }
            AuthError::SecretStoreError(e) => {
                write!(f, "secret store error: {e}")
            }
        }
    }
}

// std::error::Error requires Debug + Display. The `source()` method enables
// error chaining: callers can traverse the error chain to find root causes.
impl<E: fmt::Debug + fmt::Display> std::error::Error for AuthError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AuthError::SecretStoreError(e) => Some(e),
            _ => None,
        }
    }
}

/// Convenience conversion: allows using the `?` operator on `SecretStoreError`
/// inside functions that return `Result<_, AuthError<E>>`.
impl<E> From<SecretStoreError> for AuthError<E> {
    fn from(e: SecretStoreError) -> Self {
        AuthError::SecretStoreError(e)
    }
}

/// Errors that can occur when constructing an [`AuthenticationLayer`](super::AuthenticationLayer)
/// from an [`AtlasCLIConfig`](crate::config::AtlasCLIConfig).
///
/// These are *setup-time* errors (not per-request errors like [`AuthError`]).
/// They indicate that the config or secret store doesn't contain enough
/// information to construct the authentication layer.
#[derive(Debug, thiserror::Error)]
pub enum FromConfigError {
    /// The config doesn't specify an `auth_type`.
    #[error("auth_type is not set in the config")]
    MissingAuthType,

    /// No secret was found in the secret store for the configured profile
    /// and auth type.
    #[error("no credentials found in the secret store for this profile and auth type")]
    SecretNotFound,

    /// The secret stored in the secret store doesn't match the configured
    /// `auth_type` (e.g., config says `UserAccount` but the secret store
    /// contains `ApiKeys`).
    #[error("secret type in store doesn't match the configured auth_type")]
    AuthTypeMismatch,

    /// An error from the secret store.
    #[error("secret store error: {0}")]
    SecretStoreError(#[from] SecretStoreError),
}
