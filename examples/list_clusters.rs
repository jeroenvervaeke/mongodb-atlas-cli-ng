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
use serde::Deserialize;

use mongodb_atlas_cli::atlas::{client::AtlasClient, operation};

// Docs: https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-listgroupclusters
#[derive(Debug)]
#[operation(method = GET, version = "2024-08-05")]
#[url("/api/atlas/v2/groups/{group_id}/clusters")]
#[response(paginated, ClusterSummary)]
struct ListGroupClusterRequest {}

#[derive(Debug, Deserialize)]
pub struct ClusterSummary {
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

    let op = ListGroupClusterOperation::builder()
        .url_parameters(
            ListGroupClusterOperationUrlParams::builder()
                .group_id(group_id.clone())
                .build(),
        )
        .build();

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
