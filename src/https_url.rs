use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use url::Url;

/// An absolute `https://` URL.
///
/// Keeps the spelling it was created from: OAuth issuers are compared as
/// strings, and parsing alone would normalise them (for example by adding a
/// trailing slash).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HttpsUrl {
    raw: String,
    parsed: Url,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid URL {0:?}: must be an absolute https URL")]
pub struct InvalidHttpsUrl(String);

impl HttpsUrl {
    pub fn new(url: impl Into<String>) -> Result<Self, InvalidHttpsUrl> {
        let raw = url.into();
        match Url::parse(&raw) {
            Ok(parsed) if parsed.scheme() == "https" && parsed.has_host() => {
                Ok(Self { raw, parsed })
            }
            _ => Err(InvalidHttpsUrl(raw)),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn as_url(&self) -> &Url {
        &self.parsed
    }
}

impl TryFrom<String> for HttpsUrl {
    type Error = InvalidHttpsUrl;

    fn try_from(url: String) -> Result<Self, Self::Error> {
        Self::new(url)
    }
}

impl FromStr for HttpsUrl {
    type Err = InvalidHttpsUrl;

    fn from_str(url: &str) -> Result<Self, Self::Err> {
        Self::new(url)
    }
}

impl From<HttpsUrl> for String {
    fn from(url: HttpsUrl) -> Self {
        url.raw
    }
}

impl fmt::Display for HttpsUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_absolute_https_urls_and_keeps_their_spelling() {
        for url in [
            "https://authorize.mongodb.com",
            "https://example.com/tenant/",
        ] {
            assert_eq!(HttpsUrl::new(url).unwrap().as_str(), url);
        }
    }

    #[test]
    fn rejects_everything_else() {
        for url in [
            "",
            "authorize.mongodb.com",
            "http://authorize.mongodb.com",
            "https://",
            "/relative",
        ] {
            assert!(HttpsUrl::new(url).is_err(), "{url}");
        }
    }
}
