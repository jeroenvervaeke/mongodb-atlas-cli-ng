use std::path::Path;

use config::{Config, ConfigError, Environment};

use serde::Deserialize;
use source::{AtlasCLIGlobalConfigSource, AtlasCLIProfileConfigSource};

use crate::path::GetCLICfgFilePathError;

pub mod source;

#[derive(thiserror::Error, Debug)]
pub enum LoadCLIConfigError {
    #[error("Failed to get config file path: {0}")]
    FailedToGetConfigFilePath(#[from] GetCLICfgFilePathError),

    #[error("Failed to build config: {0}")]
    FailedToBuildConfig(#[from] ConfigError),

    #[error("Unsupported config version: {0}")]
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
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum AuthType {
    #[serde(rename = "user_account")]
    UserAccount,
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
    if config_version != 2 {
        return Err(LoadCLIConfigError::UnsupportedConfigVersion(config_version));
    }

    // Get the config
    let config = config.try_deserialize::<AtlasCLIConfig>()?;

    Ok(config)
}
