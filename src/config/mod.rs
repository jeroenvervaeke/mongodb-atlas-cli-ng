use std::path::Path;

use config::{Config, ConfigError, Environment};

use serde::Deserialize;
use source::{AtlasCLIGlobalConfigSource, AtlasCLIProfileConfigSource};

use crate::{https_url::HttpsUrl, path::GetCLICfgFilePathError};

pub mod auth_server;
pub mod session;
pub mod source;

pub use session::{
    ConfigFileSessionStore, SaveUserAccountSessionError, UserAccountSession,
    UserAccountSessionStore, get_session_store,
};

/// The config version of atlas-cli-core this library is compatible with.
///
/// Other versions are rejected, older ones too: the meaning of
/// `auth_type = "user_account"` changed in version 3.
pub const SUPPORTED_CONFIG_VERSION: u32 = 3;

/// The public OAuth2 client the Atlas CLI is registered as at the
/// Authorization Server. It is the same in every environment.
const AUTH_CODE_CLIENT_ID: &str = "https://mongodb.com/products/tools/atlas-cli";

#[derive(thiserror::Error, Debug)]
pub enum LoadCLIConfigError {
    #[error("Failed to get config file path: {0}")]
    FailedToGetConfigFilePath(#[from] GetCLICfgFilePathError),

    #[error("Failed to build config: {0}")]
    FailedToBuildConfig(#[from] ConfigError),

    #[error("Unsupported config version: {0}, expected {SUPPORTED_CONFIG_VERSION}")]
    UnsupportedConfigVersion(u32),
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct AtlasCLIConfig {
    /// The image to used for local deployments
    pub local_deployment_image: Option<String>,
    /// The path to the mongosh binary
    pub mongosh_path: Option<String>,
    /// Whether telemetry is enabled or not
    pub telemetry_enabled: Option<bool>,
    /// Whether to skip the update check
    pub skip_update_check: Option<bool>,

    /// The authentication type to use
    pub auth_type: Option<AuthType>,
    /// The organization ID to use
    pub org_id: Option<String>,
    /// The project ID to use
    pub project_id: Option<String>,
    /// The service to use
    pub service: Option<Service>,
    /// The output format to use
    pub output: Option<OutputFormat>,

    /// Custom base URL for the Atlas API
    ///
    /// When set, this overrides the default service-based URL for both API
    /// requests and token endpoints. Used for dev/staging environments.
    pub ops_manager_url: Option<String>,

    /// OAuth2 client ID override. Dev/staging environments use a different
    /// client ID than production. When set, this takes priority over the
    /// hardcoded per-service defaults.
    pub client_id: Option<String>,

    /// Authorization Server issuer for `user_account` logins that are not
    /// bound to an issuer yet. Set through `MONGODB_ATLAS_AUTH_SERVER_URL`.
    pub auth_server_url: Option<HttpsUrl>,

    /// OAuth2 client ID override for `user_account` logins. Set through
    /// `MONGODB_ATLAS_AUTH_CLIENT_ID`. Not `client_id`, which is also the
    /// service account client ID.
    pub auth_client_id: Option<String>,

    /// What the profile records about the tokens of a `user_account` login.
    #[serde(flatten)]
    pub user_account_session: UserAccountSession,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum AuthType {
    /// The Authorization Code flow against the dedicated Authorization Server.
    #[serde(rename = "user_account")]
    UserAccount,
    /// The device flow, which was `user_account` before config version 3.
    #[serde(rename = "user_account_legacy")]
    UserAccountLegacy,
    #[serde(rename = "api_keys")]
    ApiKeys,
    #[serde(rename = "service_account")]
    ServiceAccount,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum Service {
    #[serde(rename = "cloud")]
    Cloud,
    #[serde(rename = "cloudgov")]
    CloudGov,
}

impl AtlasCLIConfig {
    /// Returns the base URL for API requests and token endpoints.
    ///
    /// Priority (matching the Go CLI):
    /// 1. `ops_manager_url` from the config (custom/dev environments)
    /// 2. Default URL derived from the `service` field
    pub fn base_url(&self) -> &str {
        if let Some(url) = &self.ops_manager_url {
            url.trim_end_matches('/')
        } else {
            self.service.unwrap_or(Service::Cloud).default_base_url()
        }
    }

    /// Returns the OAuth2 client ID for device-flow authentication.
    ///
    /// Priority:
    /// 1. `client_id` from the config (dev/staging environments)
    /// 2. Hardcoded per-service default (production Cloud / CloudGov)
    pub fn cli_client_id(&self) -> &str {
        if let Some(id) = &self.client_id {
            id
        } else {
            self.service.unwrap_or(Service::Cloud).cli_client_id()
        }
    }

    /// Returns the Authorization Server issuer for a `user_account` login
    /// that is not bound to an issuer yet.
    ///
    /// Priority (matching the Go CLI):
    /// 1. `auth_server_url` from the config
    /// 2. Default issuer derived from the `service` field
    pub fn auth_server_issuer(&self) -> HttpsUrl {
        self.auth_server_url.clone().unwrap_or_else(|| {
            self.service
                .unwrap_or(Service::Cloud)
                .default_auth_server_issuer()
        })
    }

    /// Returns the OAuth2 client ID for `user_account` authentication.
    ///
    /// Priority (matching the Go CLI):
    /// 1. `auth_client_id` from the config
    /// 2. The registered public client of the Atlas CLI
    pub fn auth_code_client_id(&self) -> &str {
        self.auth_client_id
            .as_deref()
            .unwrap_or(AUTH_CODE_CLIENT_ID)
    }
}

impl Service {
    /// The default base URL for this service environment.
    pub fn default_base_url(&self) -> &'static str {
        match self {
            Service::Cloud => "https://cloud.mongodb.com",
            Service::CloudGov => "https://cloud.mongodbgov.com",
        }
    }

    /// The well-known OAuth2 client ID for the Atlas CLI device flow.
    ///
    /// This is the public client ID registered with MongoDB's identity
    /// provider specifically for the Atlas CLI. It is not a secret.
    pub fn cli_client_id(&self) -> &'static str {
        match self {
            Service::Cloud => "0oabtxactgS3gHIR0297",
            Service::CloudGov => "0oabtyfelbTBdoucy297",
        }
    }

    /// The Authorization Server that issues `user_account` tokens for this
    /// service environment.
    pub fn default_auth_server_issuer(&self) -> HttpsUrl {
        let issuer = match self {
            Service::Cloud => "https://authorize.mongodb.com",
            Service::CloudGov => "https://authorize.mongodbgov.com",
        };
        HttpsUrl::new(issuer).expect("the literal is an absolute https URL")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum OutputFormat {
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "plaintext")]
    Plaintext,
}

/// Load the config from the default file and environment variables for a given profile
/// If no profile name is provided, the default profile is loaded
pub fn load_config(profile_name: Option<&str>) -> Result<AtlasCLIConfig, LoadCLIConfigError> {
    // Get the default path to the config file
    let config_file_path = crate::path::config_file()?;

    // Load the config from the file
    load_config_from_file(config_file_path, true, profile_name)
}

/// Load the config for a given file and profile, optionally loading environment variables
pub fn load_config_from_file(
    config_file_path: impl AsRef<Path>,
    load_environment_variables: bool,
    profile_name: Option<&str>,
) -> Result<AtlasCLIConfig, LoadCLIConfigError> {
    let config_file_path = config_file_path.as_ref();

    // Build the config using the same logic as the current CLI implementation
    //
    // Layers (from lowest to highest precedence):
    // 1. Load the global config
    // 2. Load the profile config
    // 3. Environment variables with legacy prefix MCLI_ (optionally loaded for testing)
    // 4. Environment variables with new prefix "MONGODB_ATLAS_" (optionally loaded for testing)
    let mut config_builder = Config::builder()
        .add_source(AtlasCLIGlobalConfigSource::new(config_file_path))
        .add_source(AtlasCLIProfileConfigSource::new(
            config_file_path,
            profile_name.unwrap_or("default"),
        ));

    // Add the environment variables if enabled
    if load_environment_variables {
        config_builder = config_builder
            .add_source(Environment::with_prefix("MCLI"))
            .add_source(Environment::with_prefix("MONGODB_ATLAS"));
    }

    // Build the config
    let config = config_builder.build()?;

    // Get the config version
    let config_version = config
        .get::<u32>("version")
        .map_err(|_| LoadCLIConfigError::UnsupportedConfigVersion(0))?;
    if config_version != SUPPORTED_CONFIG_VERSION {
        return Err(LoadCLIConfigError::UnsupportedConfigVersion(config_version));
    }

    // Get the config
    let config = config.try_deserialize::<AtlasCLIConfig>()?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_server_issuer_prefers_the_configured_url_over_the_service_default() {
        let configured = HttpsUrl::new("https://authorize.example.com").unwrap();

        for (auth_server_url, service, expected) in [
            (None, None, "https://authorize.mongodb.com"),
            (None, Some(Service::Cloud), "https://authorize.mongodb.com"),
            (
                None,
                Some(Service::CloudGov),
                "https://authorize.mongodbgov.com",
            ),
            (
                Some(configured),
                Some(Service::CloudGov),
                "https://authorize.example.com",
            ),
        ] {
            let config = AtlasCLIConfig {
                auth_server_url,
                service,
                ..Default::default()
            };
            assert_eq!(config.auth_server_issuer().as_str(), expected);
        }
    }

    #[test]
    fn auth_code_client_id_prefers_the_configured_client_id() {
        let default = AtlasCLIConfig::default();
        let configured = AtlasCLIConfig {
            auth_client_id: Some("custom-client".into()),
            ..Default::default()
        };

        assert_eq!(
            default.auth_code_client_id(),
            "https://mongodb.com/products/tools/atlas-cli"
        );
        assert_eq!(configured.auth_code_client_id(), "custom-client");
    }
}
