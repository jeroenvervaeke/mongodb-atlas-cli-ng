//! Example: Make an authenticated request to the MongoDB Atlas API.
//!
//! This example demonstrates the full setup of an authenticated HTTP client:
//! 1. Load the CLI config (profile + auth type)
//! 2. Build an `AuthenticationLayer` from the config (reads secrets automatically)
//! 3. Compose a Tower service stack with auth + user-agent + decompression
//! 4. Make a request to the Atlas API
//!
//! # Prerequisites
//!
//! You need a valid Atlas CLI config at the default config path
//! (e.g., `~/Library/Application Support/atlascli/config.toml` on macOS)
//! with credentials stored in the OS keychain or the legacy config file.
//!
//! The easiest way to set this up is to run `atlas auth login` with the
//! official Atlas CLI first, then run this example.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example use_client
//! ```

use bytes::Bytes;
use http::{HeaderValue, Request, header::USER_AGENT};
use http_body_util::{BodyExt, Full};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tower::{Service, ServiceBuilder, ServiceExt};
use tower_http::{decompression::DecompressionLayer, set_header::SetRequestHeaderLayer};

use mongodb_atlas_cli::{client::AuthenticationLayer, config, secrets::get_secret_store};

#[tokio::main]
async fn main() {
    // Initialize tracing. Control verbosity via the RUST_LOG env var:
    //   RUST_LOG=debug cargo run --example use_client
    //   RUST_LOG=mongodb_atlas_cli=debug cargo run --example use_client
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mongodb_atlas_cli=info".parse().unwrap()),
        )
        .init();

    // Install the ring crypto provider for rustls. Both ring and aws-lc-rs
    // may be compiled in (via transitive dependencies), so an explicit
    // choice is required.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install ring crypto provider");

    let profile = "default";
    println!("Using profile: {profile}");

    // Step 1: Load the CLI config for the default profile.
    let cfg = config::load_config(Some(profile)).unwrap_or_else(|e| {
        eprintln!("Failed to load config: {e}");
        std::process::exit(1);
    });
    println!("Auth type:  {:?}", cfg.auth_type);
    println!("Service:    {:?}", cfg.service);
    println!("Base URL:   {}", cfg.base_url());

    // Step 2: Get the secret store and build the authentication layer.
    //
    // The secret store reads credentials from the OS keychain (preferred)
    // or falls back to the legacy config file.
    let secret_store = get_secret_store().unwrap_or_else(|e| {
        eprintln!("Failed to open secret store: {e}");
        std::process::exit(1);
    });

    // No token acquirer needed — the middleware handles OAuth token refresh
    // internally by using the inner Tower service.
    let auth_layer =
        AuthenticationLayer::from_config(&cfg, profile, secret_store).unwrap_or_else(|e| {
            eprintln!("Failed to create auth layer: {e}");
            std::process::exit(1);
        });

    // Step 3: Build the Tower service stack with an HTTPS-capable client.
    //
    // hyper-rustls provides TLS support using rustls (pure Rust, no OpenSSL).
    // Bundled webpki roots provide Mozilla's trusted certificate authorities.
    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let http_client = Client::builder(TokioExecutor::new()).build(https_connector);

    // Layers are applied bottom-to-top: the request flows through
    // SetRequestHeader → AuthenticationLayer → DecompressionLayer → Client.
    let mut client = ServiceBuilder::new()
        .layer(SetRequestHeaderLayer::overriding(
            USER_AGENT,
            HeaderValue::from_static("mongodb-atlas-cli-ng/0.0.1"),
        ))
        .layer(auth_layer)
        .layer(DecompressionLayer::new())
        .service(http_client);

    // Step 4: Make an authenticated request.
    //
    // The URI is built from the config's base URL so that dev/staging
    // environments (e.g., cloud-dev.mongodb.com) are supported automatically.
    let uri = format!("{}/api/atlas/v2/groups", cfg.base_url());
    println!("\nRequesting: {uri}");

    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("Accept", "application/vnd.atlas.2024-08-05+json")
        .body(Full::<Bytes>::default())
        .unwrap();

    match client.ready().await {
        Ok(ready_client) => match ready_client.call(request).await {
            Ok(response) => {
                println!("Status: {}", response.status());
                let body = response.into_body();
                let bytes = body.collect().await.unwrap().to_bytes();
                println!("Body: {}", String::from_utf8_lossy(&bytes));
            }
            Err(e) => {
                eprintln!("Request failed: {e}");
            }
        },
        Err(e) => {
            eprintln!("Service not ready: {e}");
        }
    }
}
