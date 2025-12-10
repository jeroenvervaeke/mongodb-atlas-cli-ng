use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use config::{ConfigError, Value, ValueKind};
pub use global::AtlasCLIGlobalConfigSource;
pub use profile::AtlasCLIProfileConfigSource;

pub mod global;
pub mod profile;

#[derive(thiserror::Error, Debug)]
pub enum AtlasCLIConfigSourceError {
    #[error("Failed to read file: {0}")]
    FailedToReadFile(PathBuf, std::io::Error),

    #[error("Failed to parse TOML: {0}")]
    FailedToParseTOML(#[from] toml::de::Error),

    #[error("Invalid root, was expecting table")]
    InvalidRootExpectedTable,

    #[error("Invalid profile, was expecting table")]
    InvalidProfileExpectedTable,
}

impl From<AtlasCLIConfigSourceError> for ConfigError {
    fn from(error: AtlasCLIConfigSourceError) -> Self {
        ConfigError::Foreign(Box::new(error))
    }
}

fn config_value_from_toml_file(
    origin: impl Into<String>,
    source: impl AsRef<Path>,
    root_extractor: impl FnOnce(toml::Table) -> Result<toml::Table, AtlasCLIConfigSourceError>,
) -> Result<HashMap<String, Value>, AtlasCLIConfigSourceError> {
    let source = source.as_ref();
    let origin = origin.into();

    // Read the file contents
    let file_content = std::fs::read_to_string(source)
        .map_err(|e| AtlasCLIConfigSourceError::FailedToReadFile(source.to_path_buf(), e))?;

    // Parse the TOML contents
    let toml_config: toml::Value =
        toml::from_str(&file_content).map_err(AtlasCLIConfigSourceError::FailedToParseTOML)?;

    // Get the root as a table
    let toml::Value::Table(toml_root) = toml_config else {
        return Err(AtlasCLIConfigSourceError::InvalidRootExpectedTable);
    };

    // Extract the root
    let root = root_extractor(toml_root)?;

    // Convert the root to a config value hashmap
    let mut config_value = HashMap::new();
    for (key, value) in root {
        let value_kind = match value {
            toml::Value::String(s) => Some(ValueKind::String(s.clone())),
            toml::Value::Integer(i) => Some(ValueKind::I64(i)),
            toml::Value::Float(f) => Some(ValueKind::Float(f)),
            toml::Value::Boolean(b) => Some(ValueKind::Boolean(b)),
            toml::Value::Array(_) | toml::Value::Datetime(_) | toml::Value::Table(_) => {
                // Unsupported by the CLI
                None
            }
        };

        if let Some(value_kind) = value_kind {
            config_value.insert(key.to_string(), Value::new(Some(&origin), value_kind));
        }
    }

    Ok(config_value)
}
