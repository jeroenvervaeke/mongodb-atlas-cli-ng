use bytes::Bytes;
use http::Method;
use serde::Deserialize;

use crate::atlas::{Operation, paginated::PaginatedResponse, version::Version};

// Docs: https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-listgroupclusters
// Url: /api/atlas/v2/groups/{groupId}/clusters
pub struct ListGroupClusters {
    pub group_id: String,
}

impl Operation for ListGroupClusters {
    type Response = PaginatedResponse<ClusterSummary>;

    fn method(&self) -> Method {
        Method::GET
    }

    fn url(&self) -> String {
        format!("/api/atlas/v2/groups/{}/clusters", self.group_id)
    }

    fn version(&self) -> Version {
        Version::date(2024, 8, 5)
    }

    fn body(&self) -> Bytes {
        // No body required for this operation
        Bytes::new()
    }
}

#[derive(Debug, Deserialize)]
pub struct ClusterSummary {
    pub name: String,
}
