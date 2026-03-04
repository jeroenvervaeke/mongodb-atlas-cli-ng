use bytes::Bytes;
use http::Method;
use serde::Deserialize;
use url::Url;

use crate::atlas::{Operation, version::Version};

// Docs: https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-getgroupcluster
// Url: /api/atlas/v2/groups/{groupId}/clusters/{clusterName}
pub struct GetGroupCluster {
    group_id: String,
    cluster_name: String,

}

impl Operation for GetGroupCluster {
    fn method(&self) -> Method {
        Method::GET
    }
    fn url(&self) -> Url {
        Url::parse(&format!("/api/atlas/v2/groups/{}/clusters/{}", self.group_id, self.cluster_name)).unwrap()
    }
    fn version(&self) -> Version {
        "2024-08-05".try_into().unwrap()
    }
    
    type Response = GetGroupClusterResponse;
    
    fn body(&self) -> Bytes {
        // No body required for this operation
        Bytes::new()
    }
}

pub type GetGroupClusterResponse = Vec<GetGroupClusterResponseCluster>;

#[derive(Debug, Deserialize)]
pub struct GetGroupClusterResponseCluster {
    pub name: String,
}