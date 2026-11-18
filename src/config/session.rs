//! The part of a `user_account` login that is not secret.
//!
//! The Go Atlas CLI keeps it in the profile of the config file, also when
//! the tokens themselves live in the keyring.

use std::{
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, de};
use toml::{Table, Value};
use tracing::warn;

use super::auth_server::CachedAuthServerMetadata;
use crate::{
    https_url::HttpsUrl,
    path::{GetCLICfgFilePathError, config_file},
};

const TOKEN_EXPIRY: &str = "token_expiry";
const AUTH_SERVER_ISSUER: &str = "auth_server_issuer";
const AUTH_SERVER_METADATA: &str = "auth_server_metadata";

/// What a profile records about the tokens of a `user_account` login.
///
/// Everything is optional because a token refresh restores it. Like the Go
/// Atlas CLI, an unreadable token expiry or metadata cache counts as absent.
/// An unreadable issuer is an error: falling back to another issuer would
/// send the refresh token to a server that did not issue it.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct UserAccountSession {
    /// When the access token expires.
    #[serde(default, deserialize_with = "absent_if_unreadable")]
    pub token_expiry: Option<DateTime<Utc>>,
    /// The Authorization Server that issued the tokens.
    #[serde(default, deserialize_with = "absent_if_empty")]
    pub auth_server_issuer: Option<HttpsUrl>,
    /// The cached discovery document of the Authorization Server.
    #[serde(default, deserialize_with = "absent_if_unreadable")]
    pub auth_server_metadata: Option<CachedAuthServerMetadata>,
}

/// Persists the [`UserAccountSession`] of one profile.
#[cfg_attr(test, mockall::automock)]
pub trait UserAccountSessionStore: Send + Sync {
    /// Replaces the stored session. Absent values are removed.
    fn save(&mut self, session: &UserAccountSession) -> Result<(), SaveUserAccountSessionError>;
}

#[derive(thiserror::Error, Debug)]
pub enum SaveUserAccountSessionError {
    #[error("Failed to read config file {0}: {1}")]
    ReadFile(PathBuf, std::io::Error),

    #[error("Failed to parse config file: {0}")]
    ParseFile(#[from] toml::de::Error),

    #[error("Profile {0} is not a table")]
    ProfileNotATable(String),

    #[error("Failed to serialize the authorization server metadata: {0}")]
    SerializeMetadata(#[from] serde_json::Error),

    #[error("Failed to serialize config file: {0}")]
    SerializeFile(#[from] toml::ser::Error),

    #[error("Failed to write config file {0}: {1}")]
    WriteFile(PathBuf, std::io::Error),
}

/// The session store for `profile_name` in the default config file.
pub fn get_session_store(
    profile_name: &str,
) -> Result<Box<dyn UserAccountSessionStore>, GetCLICfgFilePathError> {
    Ok(Box::new(ConfigFileSessionStore::new(
        config_file()?,
        profile_name,
    )))
}

/// Stores the session in the table of one profile of a config file.
#[derive(Clone, Debug)]
pub struct ConfigFileSessionStore {
    path: PathBuf,
    profile_name: String,
}

impl ConfigFileSessionStore {
    pub fn new(path: impl Into<PathBuf>, profile_name: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            profile_name: profile_name.into(),
        }
    }
}

impl UserAccountSessionStore for ConfigFileSessionStore {
    fn save(&mut self, session: &UserAccountSession) -> Result<(), SaveUserAccountSessionError> {
        let auth_server_metadata = session
            .auth_server_metadata
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        let mut config = read_config(&self.path)?;
        let profile = config
            .entry(self.profile_name.as_str())
            .or_insert_with(|| Value::Table(Table::new()));
        let Value::Table(profile) = profile else {
            return Err(SaveUserAccountSessionError::ProfileNotATable(
                self.profile_name.clone(),
            ));
        };

        set_or_remove(
            profile,
            TOKEN_EXPIRY,
            session
                .token_expiry
                .map(|expiry| expiry.to_rfc3339_opts(SecondsFormat::Secs, true)),
        );
        set_or_remove(
            profile,
            AUTH_SERVER_ISSUER,
            session.auth_server_issuer.clone().map(String::from),
        );
        set_or_remove(profile, AUTH_SERVER_METADATA, auth_server_metadata);

        let content = toml::to_string(&config)?;
        std::fs::write(&self.path, content)
            .map_err(|e| SaveUserAccountSessionError::WriteFile(self.path.clone(), e))
    }
}

fn read_config(path: &Path) -> Result<Table, SaveUserAccountSessionError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| SaveUserAccountSessionError::ReadFile(path.to_path_buf(), e))?;
    Ok(toml::from_str(&content)?)
}

fn set_or_remove(table: &mut Table, key: &str, value: Option<String>) {
    match value {
        Some(value) => {
            table.insert(key.to_string(), value.into());
        }
        None => {
            table.remove(key);
        }
    }
}

/// The Go Atlas CLI clears a property by writing an empty string.
fn non_empty_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.filter(|value| !value.is_empty()))
}

fn absent_if_empty<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: fmt::Display,
{
    non_empty_string(deserializer)?
        .map(|value| value.parse().map_err(de::Error::custom))
        .transpose()
}

fn absent_if_unreadable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: fmt::Display,
{
    Ok(non_empty_string(deserializer)?.and_then(|value| {
        value
            .parse()
            .inspect_err(|e| warn!(error = %e, "ignoring unreadable profile property"))
            .ok()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(toml: &str) -> Result<UserAccountSession, toml::de::Error> {
        toml::from_str(toml)
    }

    #[test]
    fn treats_cleared_and_unreadable_values_as_absent() {
        let session = session(
            "token_expiry = 'yesterday'\n\
             auth_server_issuer = ''\n\
             auth_server_metadata = '{}'",
        )
        .unwrap();

        assert_eq!(session, UserAccountSession::default());
    }

    #[test]
    fn rejects_an_issuer_that_is_not_an_https_url() {
        assert!(session("auth_server_issuer = 'http://example.com'").is_err());
    }
}
