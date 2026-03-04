//! Example: List clusters using `AtlasClient`.
//!
//! # Prerequisites
//!
//! You need a valid Atlas CLI config at the default config path
//! with credentials stored in the OS keychain or the legacy config file.
//! The easiest way is to run `atlas auth login` with the official CLI first.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example list_clusters
//! ```

use anyhow::{Context, Result};
use http::Method;
use serde::Deserialize;

use mongodb_atlas_cli::atlas::{
    Operation, Version,
    client::AtlasClient,
    paginated::{Paginated, PaginatedResponse},
};

// Docs: https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-listgroupclusters
struct ListGroupClusters {
    group_id: String,
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
}

#[derive(Debug, Deserialize)]
struct ClusterSummary {
    name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let client = AtlasClient::from_defaults().context("failed to create client")?;

    let group_id = client
        .config()
        .project_id
        .clone()
        .context("no project_id configured in profile")?;

    let op = Paginated {
        inner: ListGroupClusters { group_id },
        pagination: Default::default(),
    };

    let page = client.execute(op).await?;

    if let Some(total) = page.total_count {
        println!("Total clusters: {total}");
    }
    for cluster in &page.results {
        println!("  - {}", cluster.name);
    }
    if page.has_next() {
        println!("(more pages available)");
    }

    Ok(())
}
