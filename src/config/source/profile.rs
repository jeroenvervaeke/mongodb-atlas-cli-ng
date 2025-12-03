use std::{collections::HashMap, path::PathBuf};

use config::{ConfigError, Source, Value};

use super::{AtlasCLIConfigSourceError, config_value_from_toml_file};

#[derive(Clone, Debug)]
pub struct AtlasCLIProfileConfigSource {
    source: PathBuf,
    profile_name: String,
}

impl AtlasCLIProfileConfigSource {
    pub fn new(source: impl Into<PathBuf>, profile_name: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            profile_name: profile_name.into(),
        }
    }
}

impl Source for AtlasCLIProfileConfigSource {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new((*self).clone())
    }

    fn collect(&self) -> Result<HashMap<String, Value>, ConfigError> {
        let config = config_value_from_toml_file(
            self.profile_name.clone(),
            &self.source,
            |mut toml_config| match toml_config.remove(&self.profile_name) {
                Some(profile_config) => {
                    if let toml::Value::Table(profile_config) = profile_config {
                        Ok(profile_config)
                    } else {
                        Err(AtlasCLIConfigSourceError::InvalidProfileExpectedTable)
                    }
                }
                None => Ok(toml::Table::new()),
            },
        )?;

        Ok(config)
    }
}
