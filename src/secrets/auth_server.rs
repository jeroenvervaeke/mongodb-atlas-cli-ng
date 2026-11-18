use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::https_url::HttpsUrl;

/// OAuth Authorization Server metadata (RFC 8414) with the moment it has to be
/// discovered again.
///
/// Serializes to the JSON stored in the `auth_server_metadata` profile
/// property, shared with the Go Atlas CLI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedAuthServerMetadata {
    pub metadata: AuthServerMetadata,
    pub cache_expiry: DateTime<Utc>,
}

impl CachedAuthServerMetadata {
    /// Whether this cache can be used for `issuer` at `now`.
    pub fn is_fresh_for(&self, issuer: &HttpsUrl, now: DateTime<Utc>) -> bool {
        self.metadata.issuer == *issuer && self.cache_expiry > now
    }
}

/// The discovery document of an OAuth Authorization Server.
///
/// Fields, names and omitted empty values match the Go Atlas SDK, which reads
/// the cache this library writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthServerMetadata {
    pub issuer: HttpsUrl,
    pub authorization_endpoint: HttpsUrl,
    pub token_endpoint: HttpsUrl,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<HttpsUrl>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub authorization_response_iss_parameter_supported: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub client_id_metadata_document_supported: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cache entry exactly as the Go Atlas CLI writes it.
    const GO_CACHE: &str = r#"{"metadata":{"issuer":"https://authorize.mongodb.com","authorization_endpoint":"https://authorize.mongodb.com/authorize","token_endpoint":"https://authorize.mongodb.com/token","revocation_endpoint":"https://authorize.mongodb.com/revoke","code_challenge_methods_supported":["S256"],"client_id_metadata_document_supported":true},"cache_expiry":"2026-11-25T10:00:00.123456789+01:00"}"#;

    fn issuer(url: &str) -> HttpsUrl {
        HttpsUrl::new(url).unwrap()
    }

    #[test]
    fn reads_and_writes_the_go_cache_format() {
        let cache: CachedAuthServerMetadata = serde_json::from_str(GO_CACHE).unwrap();

        assert_eq!(
            cache.metadata.token_endpoint,
            issuer("https://authorize.mongodb.com/token")
        );
        assert!(
            !cache
                .metadata
                .authorization_response_iss_parameter_supported
        );
        assert_eq!(
            serde_json::to_string(&cache).unwrap(),
            GO_CACHE.replace("10:00:00.123456789+01:00", "09:00:00.123456789Z")
        );
    }

    #[test]
    fn rejects_metadata_with_a_non_https_endpoint() {
        let cache = GO_CACHE.replace(
            "https://authorize.mongodb.com/token",
            "http://authorize.mongodb.com/token",
        );
        assert!(serde_json::from_str::<CachedAuthServerMetadata>(&cache).is_err());
    }

    #[test]
    fn is_fresh_only_for_its_own_issuer_before_the_cache_expiry() {
        let cache: CachedAuthServerMetadata = serde_json::from_str(GO_CACHE).unwrap();
        let own = issuer("https://authorize.mongodb.com");
        let before = cache.cache_expiry - chrono::TimeDelta::seconds(1);

        assert!(cache.is_fresh_for(&own, before));
        assert!(!cache.is_fresh_for(&own, cache.cache_expiry));
        assert!(!cache.is_fresh_for(&issuer("https://authorize.mongodbgov.com"), before));
    }
}
