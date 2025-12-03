use std::{collections::HashMap, path::PathBuf};

use config::{ConfigError, Source, Value};

use super::config_value_from_toml_file;

#[derive(Clone, Debug)]
pub struct AtlasCLIGlobalConfigSource {
    source: PathBuf,
}

impl AtlasCLIGlobalConfigSource {
    pub fn new(source: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
        }
    }
}

impl Source for AtlasCLIGlobalConfigSource {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new((*self).clone())
    }

    fn collect(&self) -> Result<HashMap<String, Value>, ConfigError> {
        let config =
            config_value_from_toml_file("global", &self.source, |toml_config| Ok(toml_config))?;

        Ok(config)
    }
}
