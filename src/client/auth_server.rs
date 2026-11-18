//! Discovery of the OAuth Authorization Server that issues `user_account`
//! tokens (RFC 8414).

use std::fmt;

use bytes::{Buf, Bytes};
use chrono::{DateTime, TimeDelta, Utc};
use http::{
    HeaderMap, Request, Response,
    header::{ACCEPT, CACHE_CONTROL, EXPIRES},
};
use http_body::Body;
use http_body_util::BodyExt;
use tower::Service;
use tracing::debug;
use url::Url;

use crate::{
    https_url::HttpsUrl,
    secrets::auth_server::{AuthServerMetadata, CachedAuthServerMetadata},
};

const WELL_KNOWN_PATH: &str = "/.well-known/oauth-authorization-server";

/// How long metadata is cached when the response says nothing about caching.
/// Same as the Go Atlas SDK.
const DEFAULT_CACHE_TTL: TimeDelta = TimeDelta::days(7);

#[derive(Debug, thiserror::Error)]
pub(crate) enum DiscoveryError {
    #[error("authorization server discovery request failed: {0}")]
    Request(String),

    #[error("authorization server discovery endpoint returned HTTP {0}")]
    Status(u16),

    #[error("authorization server discovery response is invalid: {0}")]
    InvalidMetadata(#[from] serde_json::Error),

    #[error("authorization server discovery issuer {actual} does not match issuer {expected}")]
    IssuerMismatch {
        expected: HttpsUrl,
        actual: HttpsUrl,
    },
}

/// Fetch the metadata of `issuer` through the provided Tower service.
///
/// The caller is responsible for readying the service first.
pub(crate) async fn discover<S, ReqBody, ResBody>(
    inner: &mut S,
    issuer: &HttpsUrl,
) -> Result<CachedAuthServerMetadata, DiscoveryError>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Error: fmt::Debug,
    ReqBody: From<Bytes>,
    ResBody: Body,
    ResBody::Data: Buf,
    ResBody::Error: fmt::Debug,
{
    let url = discovery_url(issuer);
    debug!(url = %url, "discovering authorization server");

    let request = Request::get(url.as_str())
        .header(ACCEPT, "application/json")
        .body(ReqBody::from(Bytes::new()))
        .map_err(|e| DiscoveryError::Request(e.to_string()))?;

    let response = inner
        .call(request)
        .await
        .map_err(|e| DiscoveryError::Request(format!("{e:?}")))?;

    if !response.status().is_success() {
        return Err(DiscoveryError::Status(response.status().as_u16()));
    }

    let (parts, body) = response.into_parts();
    let body = BodyExt::collect(body)
        .await
        .map_err(|e| DiscoveryError::Request(format!("{e:?}")))?
        .to_bytes();

    let metadata: AuthServerMetadata = serde_json::from_slice(&body)?;
    if metadata.issuer != *issuer {
        return Err(DiscoveryError::IssuerMismatch {
            expected: issuer.clone(),
            actual: metadata.issuer,
        });
    }

    Ok(CachedAuthServerMetadata {
        metadata,
        cache_expiry: cache_expiry(&parts.headers, Utc::now()),
    })
}

/// The well-known path goes in front of the issuer's own path (RFC 8414 §3.1).
fn discovery_url(issuer: &HttpsUrl) -> Url {
    let mut url = issuer.as_url().clone();
    let path = match url.path() {
        "/" => WELL_KNOWN_PATH.to_string(),
        issuer_path => format!("{WELL_KNOWN_PATH}{issuer_path}"),
    };
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

/// When a discovery response received at `now` has to be fetched again.
///
/// Same rules as the Go Atlas SDK: `no-cache`/`no-store` expire at once, then
/// `max-age`, then `Expires`, then the default lifetime.
fn cache_expiry(headers: &HeaderMap, now: DateTime<Utc>) -> DateTime<Utc> {
    let mut max_age = None;
    let directives = headers
        .get_all(CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','));

    for directive in directives {
        let (name, value) = match directive.split_once('=') {
            Some((name, value)) => (name.trim(), Some(value.trim().trim_matches('"'))),
            None => (directive.trim(), None),
        };

        if name.eq_ignore_ascii_case("no-cache") || name.eq_ignore_ascii_case("no-store") {
            return now;
        }
        if name.eq_ignore_ascii_case("max-age")
            && let Some(seconds) = value.and_then(|value| value.parse::<u32>().ok())
        {
            max_age = Some(TimeDelta::seconds(i64::from(seconds)));
        }
    }

    let expires = || {
        let expires = headers.get(EXPIRES)?.to_str().ok()?;
        let expires = DateTime::parse_from_rfc2822(expires).ok()?;
        Some(expires.with_timezone(&Utc))
    };

    max_age
        .map(|max_age| now + max_age)
        .or_else(expires)
        .unwrap_or(now + DEFAULT_CACHE_TTL)
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        future::{Ready, ready},
        task::{Context, Poll},
    };

    use http::{HeaderValue, StatusCode};
    use http_body_util::Full;

    use super::*;

    const ISSUER: &str = "https://authorize.mongodb.com";

    /// Answers every request with the same response and remembers the last URI.
    struct StubService {
        status: StatusCode,
        body: String,
        requested: Option<http::Uri>,
    }

    impl Service<Request<Full<Bytes>>> for StubService {
        type Response = Response<Full<Bytes>>;
        type Error = Infallible;
        type Future = Ready<Result<Self::Response, Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<Full<Bytes>>) -> Self::Future {
            self.requested = Some(request.uri().clone());
            ready(Ok(Response::builder()
                .status(self.status)
                .header(CACHE_CONTROL, "max-age=60")
                .body(Full::new(Bytes::from(self.body.clone())))
                .unwrap()))
        }
    }

    fn metadata_document(issuer: &str) -> String {
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
        })
        .to_string()
    }

    async fn discover_with(
        status: StatusCode,
        body: String,
    ) -> (
        Result<CachedAuthServerMetadata, DiscoveryError>,
        Option<http::Uri>,
    ) {
        let mut service = StubService {
            status,
            body,
            requested: None,
        };
        let result = discover(&mut service, &HttpsUrl::new(ISSUER).unwrap()).await;
        (result, service.requested)
    }

    fn headers(pairs: &[(http::HeaderName, &'static str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| (name.clone(), HeaderValue::from_static(value)))
            .collect()
    }

    #[test]
    fn discovery_url_puts_the_well_known_path_before_the_issuer_path() {
        for (issuer, expected) in [
            (
                ISSUER,
                "https://authorize.mongodb.com/.well-known/oauth-authorization-server",
            ),
            (
                "https://authorize.mongodb.com/",
                "https://authorize.mongodb.com/.well-known/oauth-authorization-server",
            ),
            (
                "https://example.com/tenant/a?x=1#y",
                "https://example.com/.well-known/oauth-authorization-server/tenant/a",
            ),
        ] {
            let url = discovery_url(&HttpsUrl::new(issuer).unwrap());
            assert_eq!(url.as_str(), expected);
        }
    }

    #[test]
    fn cache_expiry_follows_the_cache_headers() {
        let now: DateTime<Utc> = "2026-11-18T10:00:00Z".parse().unwrap();
        let expires = (EXPIRES, "Wed, 18 Nov 2026 12:00:00 GMT");

        for (headers, expected) in [
            (headers(&[]), "2026-11-25T10:00:00Z"),
            (
                headers(&[(CACHE_CONTROL, "public, max-age=3600")]),
                "2026-11-18T11:00:00Z",
            ),
            (
                headers(&[(CACHE_CONTROL, "Max-Age=\"60\""), expires.clone()]),
                "2026-11-18T10:01:00Z",
            ),
            (
                headers(&[(CACHE_CONTROL, "max-age=3600, no-store")]),
                "2026-11-18T10:00:00Z",
            ),
            (
                headers(&[(CACHE_CONTROL, "max-age=soon"), expires.clone()]),
                "2026-11-18T12:00:00Z",
            ),
            (headers(&[(EXPIRES, "tomorrow")]), "2026-11-25T10:00:00Z"),
        ] {
            let expected: DateTime<Utc> = expected.parse().unwrap();
            assert_eq!(cache_expiry(&headers, now), expected, "{headers:?}");
        }
    }

    #[tokio::test]
    async fn discover_returns_the_metadata_with_its_cache_expiry() {
        let before = Utc::now();
        let (result, requested) = discover_with(StatusCode::OK, metadata_document(ISSUER)).await;
        let cached = result.unwrap();

        assert_eq!(
            requested.unwrap(),
            "https://authorize.mongodb.com/.well-known/oauth-authorization-server"
        );
        assert_eq!(
            cached.metadata.token_endpoint.as_str(),
            "https://authorize.mongodb.com/token"
        );
        assert!(cached.cache_expiry >= before + TimeDelta::seconds(60));
        assert!(cached.cache_expiry <= Utc::now() + TimeDelta::seconds(60));
    }

    #[tokio::test]
    async fn discover_rejects_metadata_of_another_issuer() {
        let (result, _) =
            discover_with(StatusCode::OK, metadata_document("https://evil.example")).await;

        assert!(matches!(result, Err(DiscoveryError::IssuerMismatch { .. })));
    }

    #[tokio::test]
    async fn discover_rejects_an_error_status() {
        let (result, _) = discover_with(StatusCode::NOT_FOUND, metadata_document(ISSUER)).await;

        assert!(matches!(result, Err(DiscoveryError::Status(404))));
    }

    #[tokio::test]
    async fn discover_rejects_an_invalid_document() {
        let (result, _) = discover_with(StatusCode::OK, r#"{"issuer": 1}"#.to_string()).await;

        assert!(matches!(result, Err(DiscoveryError::InvalidMetadata(_))));
    }
}
