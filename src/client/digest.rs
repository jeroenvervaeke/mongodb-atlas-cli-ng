//! HTTP Digest authentication helpers.
//!
//! This module provides functions for the HTTP Digest authentication
//! challenge-response flow, using the [`digest_auth`] crate for the
//! cryptographic heavy lifting.
//!
//! # How HTTP Digest Auth Works
//!
//! Unlike Basic auth (which sends credentials in plaintext), Digest auth
//! uses a challenge-response protocol that never sends the password over
//! the wire:
//!
//! ```text
//! Client                              Server
//!   |                                    |
//!   |--- GET /resource (no auth) ------->|
//!   |                                    |
//!   |<-- 401 + WWW-Authenticate: --------|
//!   |    Digest realm="...",             |
//!   |    nonce="...", qop="auth"         |
//!   |                                    |
//!   |--- GET /resource + Authorization: -|
//!   |    Digest username="...",          |
//!   |    response="<hash>", ...          |
//!   |                                    |
//!   |<-- 200 OK -------------------------|
//! ```
//!
//! The response hash is computed as:
//! ```text
//! HA1 = H(username:realm:password)
//! HA2 = H(method:uri)
//! response = H(HA1:nonce:nc:cnonce:qop:HA2)
//! ```
//!
//! Where `H` is typically MD5 (RFC 2617) or SHA-256 (RFC 7616). The
//! [`digest_auth`] crate supports both and negotiates based on the
//! server's `algorithm` parameter.

use std::borrow::Cow;

use digest_auth::{AuthContext, HttpMethod, WwwAuthenticateHeader};
use http::header::WWW_AUTHENTICATE;
use http::{HeaderValue, Response, StatusCode};

use super::error::AuthError;

/// Extract a Digest authentication challenge from an HTTP response.
///
/// Checks if the response is a `401 Unauthorized` with a
/// `WWW-Authenticate: Digest ...` header. If so, parses the challenge
/// and returns the parsed [`WwwAuthenticateHeader`].
///
/// Returns `Ok(None)` if:
/// - The response status is not 401
/// - There's no `WWW-Authenticate` header
/// - The `WWW-Authenticate` header uses a different scheme (e.g., Basic)
///
/// Returns `Err(AuthError::DigestAuthFailed)` if the header is present
/// and starts with "Digest" but can't be parsed.
pub fn extract_digest_challenge<B, E>(
    response: &Response<B>,
) -> Result<Option<WwwAuthenticateHeader>, AuthError<E>> {
    if response.status() != StatusCode::UNAUTHORIZED {
        return Ok(None);
    }

    let Some(www_auth) = response.headers().get(WWW_AUTHENTICATE) else {
        return Ok(None);
    };

    // The header value must be valid ASCII for digest auth
    let www_auth_str = www_auth.to_str().map_err(|e| {
        AuthError::DigestAuthFailed(format!("non-ASCII WWW-Authenticate header: {e}"))
    })?;

    // Only handle Digest challenges — ignore Basic, Bearer, etc.
    if !www_auth_str.starts_with("Digest ") {
        return Ok(None);
    }

    // Parse the challenge header into its components (realm, nonce, qop,
    // algorithm, opaque, etc.). The digest_auth crate handles all the
    // parsing complexity defined in RFC 2617 and 7616.
    let challenge = digest_auth::parse(www_auth_str).map_err(|e| {
        AuthError::DigestAuthFailed(format!("failed to parse digest challenge: {e}"))
    })?;

    Ok(Some(challenge))
}

/// Compute an `Authorization: Digest ...` header value from a challenge.
///
/// Takes a parsed digest challenge (from [`extract_digest_challenge`]),
/// the user's credentials, and the request details (method, URI), and
/// computes the appropriate digest response hash.
///
/// The [`digest_auth`] crate handles all the cryptographic details:
/// - Generating a random `cnonce` (client nonce) for replay protection
/// - Computing the response hash using MD5 or SHA-256 (server-negotiated)
/// - Formatting the complete `Authorization: Digest ...` header value
/// - Tracking the nonce count (`nc`) for nonce reuse
///
/// # Arguments
///
/// * `challenge` - Mutable because the `digest_auth` crate tracks the nonce
///   count (`nc`) internally, incrementing it on each call to `respond()`.
/// * `username` - The public API key (used as the digest username).
/// * `password` - The private API key (used as the digest password).
/// * `method` - The HTTP method string (e.g., "GET", "POST").
/// * `uri` - The request URI path (e.g., "/api/atlas/v2/groups").
pub fn compute_authorization_header<E>(
    challenge: &mut WwwAuthenticateHeader,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
) -> Result<HeaderValue, AuthError<E>> {
    // The digest_auth crate uses Cow<str> for its string fields,
    // allowing both borrowed and owned strings. We use Cow::Borrowed
    // since we already have string slices.
    let context = AuthContext {
        username: Cow::Borrowed(username),
        password: Cow::Borrowed(password),
        uri: Cow::Borrowed(uri),
        // The body is only needed for qop=auth-int (integrity protection).
        // MongoDB Atlas uses qop=auth, which only protects the URI.
        body: None,
        method: HttpMethod(Cow::Owned(method.to_string())),
        // When cnonce is None, digest_auth generates a cryptographically
        // random one automatically. Only set this for testing.
        cnonce: None,
    };

    // Compute the digest response. This performs:
    //   HA1 = H(username:realm:password)
    //   HA2 = H(method:uri)
    //   response = H(HA1:nonce:nc:cnonce:qop:HA2)
    // where H is MD5 or SHA-256 depending on the server's algorithm parameter.
    let answer = challenge.respond(&context).map_err(|e| {
        AuthError::DigestAuthFailed(format!("failed to compute digest response: {e}"))
    })?;

    // The to_string() output is the complete header value:
    //   Digest username="...", realm="...", nonce="...", uri="...", response="...", ...
    HeaderValue::from_str(&answer.to_string()).map_err(|e| {
        AuthError::DigestAuthFailed(format!("digest header contains invalid characters: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;

    #[test]
    fn extract_challenge_from_401_with_digest() {
        let response = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                WWW_AUTHENTICATE,
                r#"Digest realm="test@example.org", qop="auth", algorithm=MD5, nonce="abc123", opaque="xyz""#,
            )
            .body(Full::<Bytes>::new(Bytes::new()))
            .unwrap();

        let challenge: Result<Option<WwwAuthenticateHeader>, AuthError<String>> =
            extract_digest_challenge(&response);

        assert!(challenge.is_ok());
        let challenge = challenge.unwrap();
        assert!(challenge.is_some());

        let challenge = challenge.unwrap();
        assert_eq!(challenge.realm, "test@example.org");
        assert_eq!(challenge.nonce, "abc123");
    }

    #[test]
    fn extract_challenge_returns_none_for_200() {
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(Full::<Bytes>::new(Bytes::new()))
            .unwrap();

        let challenge: Result<Option<WwwAuthenticateHeader>, AuthError<String>> =
            extract_digest_challenge(&response);

        assert!(challenge.unwrap().is_none());
    }

    #[test]
    fn extract_challenge_returns_none_for_basic_auth() {
        let response = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(WWW_AUTHENTICATE, "Basic realm=\"test\"")
            .body(Full::<Bytes>::new(Bytes::new()))
            .unwrap();

        let challenge: Result<Option<WwwAuthenticateHeader>, AuthError<String>> =
            extract_digest_challenge(&response);

        assert!(challenge.unwrap().is_none());
    }

    #[test]
    fn extract_challenge_returns_none_for_401_without_header() {
        let response = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Full::<Bytes>::new(Bytes::new()))
            .unwrap();

        let challenge: Result<Option<WwwAuthenticateHeader>, AuthError<String>> =
            extract_digest_challenge(&response);

        assert!(challenge.unwrap().is_none());
    }

    #[test]
    fn compute_digest_header_produces_valid_output() {
        let www_auth = r#"Digest realm="test@example.org", qop="auth", algorithm=MD5, nonce="test-nonce", opaque="test-opaque""#;
        let mut challenge = digest_auth::parse(www_auth).unwrap();

        let header: Result<HeaderValue, AuthError<String>> = compute_authorization_header(
            &mut challenge,
            "my-username",
            "my-password",
            "GET",
            "/api/v2/test",
        );

        assert!(header.is_ok());
        let header = header.unwrap();
        let header_str = header.to_str().unwrap();

        assert!(header_str.starts_with("Digest "));
        assert!(header_str.contains("username=\"my-username\""));
        assert!(header_str.contains("realm=\"test@example.org\""));
        assert!(header_str.contains("nonce=\"test-nonce\""));
        assert!(header_str.contains("uri=\"/api/v2/test\""));
        assert!(header_str.contains("response=\""));
    }
}
