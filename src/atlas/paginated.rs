use bytes::Bytes;
use http::Method;
use serde::Deserialize;

use super::Operation;
use super::version::Version;

/// Query parameters for Atlas paginated list endpoints.
///
/// Maps to the server-side `pageNum`, `itemsPerPage`, and `includeCount`
/// query parameters. All fields are optional — omitted fields use the
/// server defaults (pageNum=1, itemsPerPage=100, includeCount=true).
#[derive(Debug, Clone, Default)]
pub struct PaginationRequest {
    pub page_num: Option<u32>,
    pub items_per_page: Option<u32>,
    pub include_count: Option<bool>,
}

impl PaginationRequest {
    /// Appends the pagination query parameters to a URL path string.
    pub fn append_to(&self, url: &mut String) {
        let mut first = !url.contains('?');
        let mut param = |key: &str, value: &str| {
            url.push(if first { '?' } else { '&' });
            first = false;
            url.push_str(key);
            url.push('=');
            url.push_str(value);
        };
        if let Some(n) = self.page_num {
            param("pageNum", &n.to_string());
        }
        if let Some(n) = self.items_per_page {
            param("itemsPerPage", &n.to_string());
        }
        if let Some(b) = self.include_count {
            param("includeCount", if b { "true" } else { "false" });
        }
    }
}

/// Wraps any [`Operation`] to add pagination query parameters to the request.
///
/// The inner operation's response type is passed through unchanged — it should
/// already be `PaginatedResponse<T>` for list endpoints.
pub struct Paginated<O> {
    pub inner: O,
    pub pagination: PaginationRequest,
}

impl<O: Operation> Operation for Paginated<O> {
    type Response = O::Response;

    fn method(&self) -> Method {
        self.inner.method()
    }

    fn url(&self) -> String {
        let mut url = self.inner.url();
        self.pagination.append_to(&mut url);
        url
    }

    fn version(&self) -> Version {
        self.inner.version()
    }

    fn body(&self) -> Bytes {
        self.inner.body()
    }
}

/// Generic paginated response envelope returned by Atlas list endpoints.
///
/// All Atlas Admin API list endpoints share the same structure:
/// `results` holds the page items, `total_count` the full collection size
/// (when `includeCount=true`), and `links` the HATEOAS navigation links
/// (`self`, `next`, `previous`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResponse<T> {
    pub results: Vec<T>,
    #[serde(default)]
    pub total_count: Option<u64>,
    #[serde(default)]
    pub links: Vec<Link>,
}

#[derive(Debug, Deserialize)]
pub struct Link {
    pub rel: String,
    pub href: String,
}

impl<T> PaginatedResponse<T> {
    pub fn next_link(&self) -> Option<&str> {
        self.links
            .iter()
            .find(|l| l.rel == "next")
            .map(|l| l.href.as_str())
    }

    pub fn previous_link(&self) -> Option<&str> {
        self.links
            .iter()
            .find(|l| l.rel == "previous")
            .map(|l| l.href.as_str())
    }

    pub fn has_next(&self) -> bool {
        self.next_link().is_some()
    }
}
