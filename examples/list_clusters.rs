//! Example: List clusters using the Operation layer.
//!
//! Demonstrates the `OperationLayer` which converts typed `Operation` structs
//! into HTTP requests and deserializes the response automatically.
//!
//! # Prerequisites
//!
//! Same as `use_client` — you need a valid Atlas CLI config with credentials
//! and a `project_id` set in the profile.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example list_clusters
//! ```

use http::{HeaderValue, header::USER_AGENT};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tower::{ServiceBuilder, ServiceExt};
use tower_http::{decompression::DecompressionLayer, set_header::SetRequestHeaderLayer};

use mongodb_atlas_cli::{
    atlas::{layer::OperationLayer, operations::ListGroupClusters, paginated::Paginated},
    client::AuthenticationLayer,
    config,
    secrets::get_secret_store,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mongodb_atlas_cli=info".parse().unwrap()),
        )
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install ring crypto provider");

    let profile = "default";
    let cfg = config::load_config(Some(profile)).unwrap_or_else(|e| {
        eprintln!("Failed to load config: {e}");
        std::process::exit(1);
    });

    let group_id = cfg.project_id.clone().unwrap_or_else(|| {
        eprintln!("No project_id configured in profile '{profile}'");
        std::process::exit(1);
    });

    let secret_store = get_secret_store().unwrap_or_else(|e| {
        eprintln!("Failed to open secret store: {e}");
        std::process::exit(1);
    });

    let auth_layer =
        AuthenticationLayer::from_config(&cfg, profile, secret_store).unwrap_or_else(|e| {
            eprintln!("Failed to create auth layer: {e}");
            std::process::exit(1);
        });

    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let http_client = Client::builder(TokioExecutor::new()).build(https_connector);

    let client = ServiceBuilder::new()
        .layer(OperationLayer::new(cfg))
        .layer(SetRequestHeaderLayer::overriding(
            USER_AGENT,
            HeaderValue::from_static("mongodb-atlas-cli-ng/0.0.1"),
        ))
        .layer(auth_layer)
        .layer(DecompressionLayer::new())
        .service(http_client);

    let op = Paginated {
        inner: ListGroupClusters { group_id },
        pagination: Default::default(),
    };

    match client.oneshot(op).await {
        Ok(page) => {
            if let Some(total) = page.total_count {
                println!("Total clusters: {total}");
            }
            for cluster in &page.results {
                println!("  - {}", cluster.name);
            }
            if page.has_next() {
                println!("(more pages available)");
            }
        }
        Err(e) => eprintln!("Request failed: {e}"),
    }
}
