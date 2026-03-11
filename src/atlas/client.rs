use bytes::Bytes;
use http::{HeaderValue, header::USER_AGENT};
use http_body_util::Full;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use tower::{ServiceBuilder, ServiceExt};
use tower_http::{decompression::DecompressionLayer, set_header::SetRequestHeaderLayer};

use super::Operation;
use super::layer::{OperationError, OperationLayer};
use crate::client::AuthenticationLayer;
use crate::config::{self, AtlasCLIConfig};
use crate::secrets::{self, SecretStore};

#[derive(thiserror::Error, Debug)]
pub enum AtlasClientError {
    #[error("failed to load config: {0}")]
    Config(#[from] config::LoadCLIConfigError),

    #[error("failed to open secret store: {0}")]
    SecretStore(#[from] secrets::SecretStoreError),

    #[error("failed to create auth layer: {0}")]
    Auth(#[from] crate::client::FromConfigError),
}

/// High-level client for the MongoDB Atlas Admin API.
///
/// Wraps the Tower middleware stack (HTTPS, auth, decompression, operation layer)
/// so callers can pass an [`Operation`] and get back the typed response directly.
///
/// # Construction
///
/// Three constructors are available, from most to least configurable:
///
/// - [`AtlasClient::new`] — full control: caller provides config, profile, and secret store.
/// - [`AtlasClient::with_profile`] — provide a profile name; config and secrets auto-loaded.
/// - [`AtlasClient::from_defaults`] — everything auto-detected using the `"default"` profile.
pub struct AtlasClient {
    config: AtlasCLIConfig,
    http_client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    auth_layer: AuthenticationLayer,
}

impl AtlasClient {
    /// Build from explicit parts — nothing loaded from disk.
    pub fn new(
        config: AtlasCLIConfig,
        profile: &str,
        secret_store: Box<dyn SecretStore>,
    ) -> Result<Self, AtlasClientError> {
        let auth_layer = AuthenticationLayer::from_config(&config, profile, secret_store)?;
        Ok(Self::build(config, auth_layer))
    }

    /// Build using a named profile — config and secret store loaded from default paths.
    pub fn with_profile(profile: &str) -> Result<Self, AtlasClientError> {
        let config = config::load_config(Some(profile))?;
        let secret_store = secrets::get_secret_store()?;
        let auth_layer = AuthenticationLayer::from_config(&config, profile, secret_store)?;
        Ok(Self::build(config, auth_layer))
    }

    /// Build with all defaults — `"default"` profile, default config path, auto-detected secrets.
    pub fn from_defaults() -> Result<Self, AtlasClientError> {
        Self::with_profile("default")
    }

    /// Execute an [`Operation`] and return its response.
    pub async fn execute<O>(&self, op: O) -> Result<O::Response, OperationError>
    where
        O: Operation + Send + 'static,
    {
        let svc = ServiceBuilder::new()
            .layer(OperationLayer::new(self.config.clone()))
            .layer(SetRequestHeaderLayer::overriding(
                USER_AGENT,
                HeaderValue::from_static(concat!(
                    "mongodb-atlas-cli-ng/",
                    env!("CARGO_PKG_VERSION")
                )),
            ))
            .layer(self.auth_layer.clone())
            .layer(DecompressionLayer::new())
            .service(self.http_client.clone());

        svc.oneshot(op).await
    }

    /// Returns the underlying config.
    pub fn config(&self) -> &AtlasCLIConfig {
        &self.config
    }

    fn build(config: AtlasCLIConfig, auth_layer: AuthenticationLayer) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        let http_client = Client::builder(TokioExecutor::new()).build(https_connector);

        Self {
            config,
            http_client,
            auth_layer,
        }
    }
}
