//! The profile tables of the CLI config file, as far as credentials use them.
//!
//! The Go Atlas CLI keeps secrets in the keyring when one is available, but
//! the other properties of a login always live in the profile's table of the
//! config file.

use std::{fmt, fs::read_to_string, path::Path};

use chrono::{DateTime, SecondsFormat, Utc};
use toml::{Table, Value};
use tracing::warn;

use super::{ProfileName, SecretStoreError, UserAccountSession};
use crate::https_url::HttpsUrl;

const TOKEN_EXPIRY: &str = "token_expiry";
const AUTH_SERVER_ISSUER: &str = "auth_server_issuer";
const AUTH_SERVER_METADATA: &str = "auth_server_metadata";

pub(super) fn read_table(path: &Path) -> Result<Table, SecretStoreError> {
    let file_content = read_to_string(path).map_err(|e| SecretStoreError::KeyStoreUnavailable {
        reason: e.to_string(),
    })?;

    toml::from_str(&file_content).map_err(|e| SecretStoreError::InvalidKeyStoreFormat {
        reason: e.to_string(),
    })
}

pub(super) fn save_table(path: &Path, table: &Table) -> Result<(), SecretStoreError> {
    let file_content = toml::to_string(table).map_err(|e| SecretStoreError::Serialization {
        reason: e.to_string(),
    })?;

    std::fs::write(path, file_content).map_err(|e| SecretStoreError::KeyStoreUnavailable {
        reason: e.to_string(),
    })
}

/// The table of `profile_name`, created when the profile does not exist yet.
pub(super) fn profile_table_mut<'a>(
    root: &'a mut Table,
    profile_name: &ProfileName,
) -> Result<&'a mut Table, SecretStoreError> {
    match root
        .entry(profile_name.as_str())
        .or_insert_with(|| Value::Table(Table::new()))
    {
        Value::Table(profile) => Ok(profile),
        _ => Err(SecretStoreError::InvalidKeyStoreFormat {
            reason: format!("Profile {profile_name} is not a table"),
        }),
    }
}

pub(super) fn optional_string(
    table: &Table,
    key: &str,
) -> Result<Option<String>, SecretStoreError> {
    match table.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(SecretStoreError::InvalidKeyStoreFormat {
            reason: format!("Key {key} is not a string"),
        }),
    }
}

/// Reads the session of a `user_account` login from its profile table.
///
/// Like the Go Atlas CLI, an unreadable token expiry or metadata cache counts
/// as absent: both are recovered by refreshing the token. An unreadable
/// issuer is an error, because falling back to another issuer would send the
/// refresh token to a server that did not issue it.
pub(super) fn read_user_account_session(
    profile: &Table,
) -> Result<UserAccountSession, SecretStoreError> {
    let auth_server_issuer = non_empty_string(profile, AUTH_SERVER_ISSUER)?
        .map(HttpsUrl::new)
        .transpose()
        .map_err(|e| SecretStoreError::InvalidKeyStoreFormat {
            reason: format!("Key {AUTH_SERVER_ISSUER}: {e}"),
        })?;

    Ok(UserAccountSession {
        token_expiry: parse_or_ignore(profile, TOKEN_EXPIRY, |value| {
            DateTime::parse_from_rfc3339(value).map(|expiry| expiry.with_timezone(&Utc))
        })?,
        auth_server_issuer,
        auth_server_metadata: parse_or_ignore(profile, AUTH_SERVER_METADATA, |value| {
            serde_json::from_str(value)
        })?,
    })
}

/// Writes the session of a `user_account` login into its profile table.
/// Absent values remove their key.
pub(super) fn write_user_account_session(
    profile: &mut Table,
    session: &UserAccountSession,
) -> Result<(), SecretStoreError> {
    let auth_server_metadata = session
        .auth_server_metadata
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| SecretStoreError::Serialization {
            reason: e.to_string(),
        })?;

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

    Ok(())
}

/// The Go Atlas CLI clears a property by writing an empty string.
fn non_empty_string(table: &Table, key: &str) -> Result<Option<String>, SecretStoreError> {
    Ok(optional_string(table, key)?.filter(|value| !value.is_empty()))
}

fn parse_or_ignore<T, E: fmt::Display>(
    table: &Table,
    key: &str,
    parse: impl FnOnce(&str) -> Result<T, E>,
) -> Result<Option<T>, SecretStoreError> {
    Ok(non_empty_string(table, key)?.and_then(|value| {
        parse(&value)
            .inspect_err(|e| warn!(key, error = %e, "ignoring unreadable profile property"))
            .ok()
    }))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::auth_server::CachedAuthServerMetadata;

    const METADATA: &str = r#"{"metadata":{"issuer":"https://authorize.mongodb.com","authorization_endpoint":"https://authorize.mongodb.com/authorize","token_endpoint":"https://authorize.mongodb.com/token"},"cache_expiry":"2026-11-25T09:00:00Z"}"#;

    fn profile(toml: &str) -> Table {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn reads_a_session_written_by_the_go_cli() {
        let session = read_user_account_session(&profile(&format!(
            "token_expiry = '2026-11-18T11:00:00+01:00'\n\
             auth_server_issuer = 'https://authorize.mongodb.com'\n\
             auth_server_metadata = '{METADATA}'"
        )))
        .unwrap();

        assert_eq!(
            session,
            UserAccountSession {
                token_expiry: Some("2026-11-18T10:00:00Z".parse().unwrap()),
                auth_server_issuer: Some(HttpsUrl::new("https://authorize.mongodb.com").unwrap()),
                auth_server_metadata: Some(
                    serde_json::from_str::<Box<CachedAuthServerMetadata>>(METADATA).unwrap()
                ),
            }
        );
    }

    #[test]
    fn treats_cleared_and_unreadable_values_as_absent() {
        let session = read_user_account_session(&profile(
            "token_expiry = 'yesterday'\n\
             auth_server_issuer = ''\n\
             auth_server_metadata = ''",
        ))
        .unwrap();

        assert_eq!(session, UserAccountSession::default());
    }

    #[test]
    fn rejects_an_issuer_that_is_not_an_https_url() {
        let result =
            read_user_account_session(&profile("auth_server_issuer = 'http://example.com'"));

        assert!(matches!(
            result,
            Err(SecretStoreError::InvalidKeyStoreFormat { .. })
        ));
    }

    #[test]
    fn writes_what_it_reads_and_removes_absent_values() {
        let mut table = profile(&format!(
            "org_id = 'kept'\n\
             token_expiry = '2026-11-18T10:00:00Z'\n\
             auth_server_issuer = 'https://authorize.mongodb.com'\n\
             auth_server_metadata = '{METADATA}'"
        ));
        let expected = table.clone();
        let session = read_user_account_session(&table).unwrap();

        write_user_account_session(&mut table, &session).unwrap();
        assert_eq!(table, expected);

        write_user_account_session(&mut table, &UserAccountSession::default()).unwrap();
        assert_eq!(table, profile("org_id = 'kept'"));
    }
}
