//! OAuth2 token types and token acquisition via the inner Tower service.
//!
//! This module provides the types used for OAuth2 token management
//! in the authentication middleware:
//!
//! - [`CachedToken`]: An in-memory cached access token with expiry tracking.
//! - [`OAuthTokenResponse`]: The parsed response from an OAuth2 token endpoint.
//! - [`OAuthError`]: Errors during token acquisition.
//! - [`acquire_token`]: Sends a token request through a Tower service.
//!
//! # Token Acquisition Architecture
//!
//! Instead of requiring callers to provide a token acquisition closure,
//! the middleware acquires tokens by making HTTP POST requests through
//! the **inner Tower service** that it already wraps. This means:
//!
//! 1. Token refresh uses the same transport as regular API requests
//!    (same TLS config, proxy settings, connection pool).
//! 2. The token request bypasses the authentication layer — you don't
//!    need authentication to *obtain* authentication.
//! 3. Users don't need to construct or wire up a separate HTTP client.

use std::fmt;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use http::{Request, Response};
use http_body::Body;
use http_body_util::BodyExt;
use tower::Service;
use tracing::{debug, warn};

/// The response from an OAuth2 token endpoint.
///
/// This struct represents the relevant fields from a JSON token response:
/// ```json
/// {
///   "access_token": "eyJhbGciOiJ...",
///   "refresh_token": "dGhpcyBpcyBh...",
///   "expires_in": 3600
/// }
/// ```
#[derive(Debug, Clone)]
pub struct OAuthTokenResponse {
    /// The access token issued by the authorization server.
    pub access_token: String,

    /// An optional new refresh token. When present, the old refresh token
    /// should be replaced — this is called "token rotation" and is a
    /// security best practice to limit the impact of leaked tokens.
    pub refresh_token: Option<String>,

    /// The lifetime of the access token in seconds.
    /// If `None`, the token has no known expiry.
    pub expires_in: Option<u64>,
}

/// Errors that can occur during OAuth2 token acquisition.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("HTTP request to token endpoint failed: {0}")]
    HttpError(String),

    #[error("Token endpoint returned invalid response: {0}")]
    InvalidResponse(String),

    #[error("Token endpoint returned error (HTTP {status}): {body}")]
    TokenEndpointError { status: u16, body: String },
}

/// Acquire an OAuth2 token by POSTing form-encoded credentials to a token endpoint.
///
/// Uses the provided Tower service (typically the inner HTTP client) to make
/// the request. This ensures token acquisition shares the same transport
/// configuration (TLS, proxies, connection pool) as regular API requests.
///
/// # Arguments
///
/// * `inner` - A Tower service that can make HTTP requests. The caller is
///   responsible for readying this service before calling `acquire_token`.
/// * `endpoint` - The OAuth2 token endpoint URL.
/// * `form_body` - The URL-encoded form body (e.g., `grant_type=refresh_token&...`).
///
/// # Type Parameters
///
/// * `ReqBody` - The request body type. Must be constructible from [`Bytes`]
///   so we can create the form-encoded POST body.
/// * `ResBody` - The response body type. Must implement [`Body`] so we can
///   read and parse the JSON token response.
pub(crate) async fn acquire_token<S, ReqBody, ResBody>(
    inner: &mut S,
    endpoint: &str,
    form_body: String,
) -> Result<OAuthTokenResponse, OAuthError>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send,
    S::Error: fmt::Debug,
    ReqBody: From<Bytes>,
    ResBody: Body,
    ResBody::Data: Buf,
    ResBody::Error: fmt::Debug,
{
    debug!(endpoint = %endpoint, "POSTing to token endpoint");

    let body = ReqBody::from(Bytes::from(form_body));
    let request = Request::post(endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .map_err(|e| OAuthError::HttpError(format!("failed to build token request: {e}")))?;

    let response = inner
        .call(request)
        .await
        .map_err(|e| OAuthError::HttpError(format!("{e:?}")))?;

    let status = response.status();
    debug!(status = %status, "token endpoint responded");

    let collected = BodyExt::collect(response.into_body())
        .await
        .map_err(|e| OAuthError::HttpError(format!("failed to read token response body: {e:?}")))?;
    let bytes = collected.to_bytes();

    if !status.is_success() {
        let body = String::from_utf8_lossy(&bytes).to_string();
        warn!(status = status.as_u16(), body = %body, "token endpoint returned error");
        return Err(OAuthError::TokenEndpointError {
            status: status.as_u16(),
            body,
        });
    }

    let token_response = parse_token_response(&bytes)?;
    debug!(
        has_refresh_token = token_response.refresh_token.is_some(),
        expires_in = ?token_response.expires_in,
        "token acquired successfully"
    );
    Ok(token_response)
}

/// Parse a JSON token endpoint response into an [`OAuthTokenResponse`].
fn parse_token_response(body: &[u8]) -> Result<OAuthTokenResponse, OAuthError> {
    let json: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| OAuthError::InvalidResponse(format!("invalid JSON: {e}")))?;

    let access_token = json["access_token"]
        .as_str()
        .ok_or_else(|| OAuthError::InvalidResponse("missing access_token field".into()))?
        .to_string();

    Ok(OAuthTokenResponse {
        access_token,
        refresh_token: json["refresh_token"].as_str().map(String::from),
        expires_in: json["expires_in"].as_u64(),
    })
}

/// An in-memory cached OAuth2 access token with optional expiry tracking.
///
/// Tokens are cached to avoid making token endpoint requests on every API call.
/// The middleware checks [`is_expired()`](CachedToken::is_expired) before each
/// request and only refreshes when the token has expired (or is about to).
///
/// # Expiry buffer
///
/// When a token response includes `expires_in`, we subtract a 30-second buffer
/// from the expiry time. This ensures we refresh *before* the token actually
/// expires, avoiding race conditions where a token expires in-flight.
#[derive(Debug, Clone)]
pub struct CachedToken {
    /// The access token string, suitable for use in an `Authorization: Bearer` header.
    pub access_token: String,

    /// When the token expires. `None` means the token has no known expiry
    /// and is treated as valid until the server rejects it.
    pub expires_at: Option<Instant>,
}

/// Buffer subtracted from token expiry to account for clock skew and network
/// latency. We refresh 30 seconds early to avoid using an almost-expired token.
const TOKEN_EXPIRY_BUFFER: Duration = Duration::from_secs(30);

impl CachedToken {
    /// Create a new cached token with no known expiry.
    ///
    /// This is typically used when loading a pre-existing token from the
    /// secret store, where we don't have information about when it was
    /// issued or when it expires.
    pub fn new(access_token: String) -> Self {
        CachedToken {
            access_token,
            expires_at: None,
        }
    }

    /// Create a cached token from an OAuth2 token response.
    ///
    /// If the response includes `expires_in`, the expiry time is calculated
    /// as `now + expires_in - buffer`. The buffer ensures we refresh before
    /// the token actually expires.
    pub fn from_response(response: &OAuthTokenResponse) -> Self {
        let expires_at = response.expires_in.map(|secs| {
            // saturating_sub prevents underflow if expires_in < buffer
            Instant::now() + Duration::from_secs(secs).saturating_sub(TOKEN_EXPIRY_BUFFER)
        });

        CachedToken {
            access_token: response.access_token.clone(),
            expires_at,
        }
    }

    /// Check if the token has expired (or is about to expire).
    ///
    /// Returns `false` if the token has no known expiry — we can't know
    /// it's expired without expiry information, so we assume it's valid
    /// and let the server tell us otherwise.
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|exp| Instant::now() >= exp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_token_without_expiry_is_not_expired() {
        let token = CachedToken::new("test-token".into());
        assert!(!token.is_expired());
    }

    #[test]
    fn cached_token_with_future_expiry_is_not_expired() {
        let token = CachedToken {
            access_token: "test-token".into(),
            expires_at: Some(Instant::now() + Duration::from_secs(3600)),
        };
        assert!(!token.is_expired());
    }

    #[test]
    fn cached_token_with_past_expiry_is_expired() {
        let token = CachedToken {
            access_token: "test-token".into(),
            expires_at: Some(Instant::now() - Duration::from_secs(60)),
        };
        assert!(token.is_expired());
    }

    #[test]
    fn from_response_computes_expiry_with_buffer() {
        let response = OAuthTokenResponse {
            access_token: "access".into(),
            refresh_token: None,
            expires_in: Some(3600),
        };
        let token = CachedToken::from_response(&response);

        // The token should expire roughly at now + 3600 - 30 = now + 3570 seconds
        assert!(!token.is_expired());
        assert!(token.expires_at.is_some());
    }

    #[test]
    fn from_response_without_expiry_creates_non_expiring_token() {
        let response = OAuthTokenResponse {
            access_token: "access".into(),
            refresh_token: None,
            expires_in: None,
        };
        let token = CachedToken::from_response(&response);

        assert!(!token.is_expired());
        assert!(token.expires_at.is_none());
    }

    #[test]
    fn parse_token_response_extracts_fields() {
        let json = serde_json::json!({
            "access_token": "my-token",
            "refresh_token": "my-refresh",
            "expires_in": 3600
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let response = parse_token_response(&bytes).unwrap();
        assert_eq!(response.access_token, "my-token");
        assert_eq!(response.refresh_token.as_deref(), Some("my-refresh"));
        assert_eq!(response.expires_in, Some(3600));
    }

    #[test]
    fn parse_token_response_handles_minimal_response() {
        let json = serde_json::json!({ "access_token": "minimal" });
        let bytes = serde_json::to_vec(&json).unwrap();
        let response = parse_token_response(&bytes).unwrap();
        assert_eq!(response.access_token, "minimal");
        assert!(response.refresh_token.is_none());
        assert!(response.expires_in.is_none());
    }

    #[test]
    fn parse_token_response_rejects_missing_access_token() {
        let json = serde_json::json!({ "refresh_token": "oops" });
        let bytes = serde_json::to_vec(&json).unwrap();
        let result = parse_token_response(&bytes);
        assert!(result.is_err());
    }
}
