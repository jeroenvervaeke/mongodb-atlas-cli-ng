//! Integration tests for the `#[operation]` macro: generated code compiles and behaves correctly.

use http::Method;

use mongodb_atlas_cli::atlas::{Operation, operation};

#[derive(Debug)]
#[operation(method = GET, version = "2024-08-05")]
#[url("/api/atlas/v2/groups/{group_id}/clusters")]
#[response(paginated, ClusterSummary)]
struct ListGroupClusterRequest {}

#[allow(dead_code)]
pub struct ClusterSummary {
    name: String,
}

#[test]
fn generated_operation_has_correct_method() {
    let op = ListGroupClusterOperation {
        url_parameters: ListGroupClusterOperationUrlParams {
            group_id: "my-group".to_string(),
        },
        pagination: Default::default(),
    };
    assert_eq!(op.method(), Method::GET);
}

#[test]
fn generated_operation_builds_url_with_params() {
    let op = ListGroupClusterOperation {
        url_parameters: ListGroupClusterOperationUrlParams {
            group_id: "abc123".to_string(),
        },
        pagination: Default::default(),
    };
    let url = op.url();
    assert!(url.contains("/groups/abc123/clusters"), "url = {}", url);
}

#[test]
fn generated_operation_version() {
    let op = ListGroupClusterOperation {
        url_parameters: ListGroupClusterOperationUrlParams {
            group_id: "x".to_string(),
        },
        pagination: Default::default(),
    };
    let v = op.version();
    let s = v.to_string();
    assert!(s.contains("2024-08-05"), "version = {}", s);
}
