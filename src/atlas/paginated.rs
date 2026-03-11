use bytes::Bytes;
use http::Method;
use serde::{Deserialize, de::DeserializeOwned};

use super::version::Version;
use super::{Operation, OperationError};

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

/// Wraps any [`Operation`] to add pagination query parameters to the URL and
/// deserialize the response as [`PaginatedResponse<O::Response>`].
///
/// Paginated responses are always JSON, so the inner operation's `parse_response`
/// is not delegated to — this wrapper handles deserialization itself.
pub struct Paginated<O> {
    pub inner: O,
    pub pagination: PaginationRequest,
}

impl<O: Operation> Operation for Paginated<O>
where
    O::Response: DeserializeOwned,
{
    type Response = PaginatedResponse<O::Response>;

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

    fn request_body(&self) -> Bytes {
        self.inner.request_body()
    }

    fn parse_response(bytes: Bytes) -> Result<Self::Response, OperationError> {
        serde_json::from_slice(&bytes).map_err(OperationError::Deserialize)
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── PaginationRequest::append_to ─────────────────────────────────────────

    #[test]
    fn append_to_empty_pagination_leaves_url_unchanged() {
        let mut url = "/api/v2/clusters".to_string();
        PaginationRequest::default().append_to(&mut url);
        assert_eq!(url, "/api/v2/clusters");
    }

    #[test]
    fn append_to_page_num_adds_query_string() {
        let mut url = "/api/v2/clusters".to_string();
        PaginationRequest {
            page_num: Some(3),
            ..Default::default()
        }
        .append_to(&mut url);
        assert_eq!(url, "/api/v2/clusters?pageNum=3");
    }

    #[test]
    fn append_to_items_per_page_adds_query_string() {
        let mut url = "/api/v2/clusters".to_string();
        PaginationRequest {
            items_per_page: Some(50),
            ..Default::default()
        }
        .append_to(&mut url);
        assert_eq!(url, "/api/v2/clusters?itemsPerPage=50");
    }

    #[test]
    fn append_to_include_count_false() {
        let mut url = "/api/v2/clusters".to_string();
        PaginationRequest {
            include_count: Some(false),
            ..Default::default()
        }
        .append_to(&mut url);
        assert_eq!(url, "/api/v2/clusters?includeCount=false");
    }

    #[test]
    fn append_to_all_params_joined_with_ampersand() {
        let mut url = "/api/v2/clusters".to_string();
        PaginationRequest {
            page_num: Some(2),
            items_per_page: Some(25),
            include_count: Some(true),
        }
        .append_to(&mut url);
        assert_eq!(
            url,
            "/api/v2/clusters?pageNum=2&itemsPerPage=25&includeCount=true"
        );
    }

    #[test]
    fn append_to_uses_ampersand_when_url_already_has_query_string() {
        let mut url = "/api/v2/clusters?envelope=false".to_string();
        PaginationRequest {
            page_num: Some(1),
            ..Default::default()
        }
        .append_to(&mut url);
        assert_eq!(url, "/api/v2/clusters?envelope=false&pageNum=1");
    }

    // ── PaginatedResponse navigation helpers ─────────────────────────────────

    fn make_response(links: Vec<(&str, &str)>) -> PaginatedResponse<()> {
        PaginatedResponse {
            results: vec![],
            total_count: None,
            links: links
                .into_iter()
                .map(|(rel, href)| Link {
                    rel: rel.to_string(),
                    href: href.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn has_next_is_false_when_no_links() {
        assert!(!make_response(vec![]).has_next());
    }

    #[test]
    fn has_next_is_true_when_next_link_present() {
        let r = make_response(vec![("next", "https://example.com/page2")]);
        assert!(r.has_next());
    }

    #[test]
    fn has_next_is_false_when_only_previous_link() {
        let r = make_response(vec![("previous", "https://example.com/page1")]);
        assert!(!r.has_next());
    }

    #[test]
    fn next_link_returns_href() {
        let r = make_response(vec![
            ("self", "https://example.com/page2"),
            ("next", "https://example.com/page3"),
        ]);
        assert_eq!(r.next_link(), Some("https://example.com/page3"));
    }

    #[test]
    fn previous_link_returns_href() {
        let r = make_response(vec![
            ("previous", "https://example.com/page1"),
            ("next", "https://example.com/page3"),
        ]);
        assert_eq!(r.previous_link(), Some("https://example.com/page1"));
    }

    #[test]
    fn previous_link_is_none_when_absent() {
        let r = make_response(vec![("next", "https://example.com/page2")]);
        assert_eq!(r.previous_link(), None);
    }

    // ── Paginated<O> wrapper ─────────────────────────────────────────────────

    /// Minimal operation whose Response is a plain item type (not pre-wrapped).
    struct ItemOp;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Item {
        name: String,
    }

    impl Operation for ItemOp {
        type Response = Item;
        fn method(&self) -> Method {
            Method::GET
        }
        fn url(&self) -> String {
            "/api/v2/items".to_string()
        }
        fn version(&self) -> Version {
            Version::date(2024, 1, 1)
        }
        fn parse_response(bytes: Bytes) -> Result<Self::Response, OperationError> {
            serde_json::from_slice(&bytes).map_err(OperationError::Deserialize)
        }
    }

    #[test]
    fn paginated_response_type_is_paginated_response_of_inner() {
        // Compile-time assertion: assigning the result of parse_response to the
        // expected type will fail to compile if Response is wrong.
        let json = br#"{"results":[{"name":"foo"}],"totalCount":1,"links":[]}"#;
        let result: PaginatedResponse<Item> =
            <Paginated<ItemOp> as Operation>::parse_response(Bytes::from_static(json)).unwrap();
        assert_eq!(result.results[0].name, "foo");
        assert_eq!(result.total_count, Some(1));
    }

    #[test]
    fn paginated_parse_response_deserializes_results() {
        let json = br#"{"results":[{"name":"a"},{"name":"b"}],"links":[]}"#;
        let r = <Paginated<ItemOp> as Operation>::parse_response(Bytes::from_static(json)).unwrap();
        assert_eq!(r.results.len(), 2);
        assert_eq!(r.results[0].name, "a");
        assert_eq!(r.results[1].name, "b");
    }

    #[test]
    fn paginated_parse_response_does_not_delegate_to_inner_parse_response() {
        // The inner op's parse_response would try to deserialize a bare `Item`,
        // but Paginated must deserialize `PaginatedResponse<Item>` instead.
        // A bare-Item JSON must fail when parsed through Paginated.
        let bare_item_json = br#"{"name":"foo"}"#;
        let result =
            <Paginated<ItemOp> as Operation>::parse_response(Bytes::from_static(bare_item_json));
        assert!(
            result.is_err(),
            "should fail: bare Item JSON is not PaginatedResponse<Item>"
        );
    }

    #[test]
    fn paginated_url_appends_pagination_to_inner_url() {
        let op = Paginated {
            inner: ItemOp,
            pagination: PaginationRequest {
                page_num: Some(2),
                ..Default::default()
            },
        };
        assert_eq!(op.url(), "/api/v2/items?pageNum=2");
    }

    #[test]
    fn paginated_delegates_method_and_version() {
        let op = Paginated {
            inner: ItemOp,
            pagination: PaginationRequest::default(),
        };
        assert_eq!(op.method(), Method::GET);
        assert_eq!(op.version(), Version::date(2024, 1, 1));
    }
}
