use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
};

use toml::{Table, Value};

use crate::{
    config::AuthType,
    secrets::{ApiKeys, ServiceAccount, UserAccount},
};

use super::{Secret, SecretStore, SecretStoreError};

pub struct LegacySecretStore {
    path: PathBuf,
}

impl LegacySecretStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl SecretStore for LegacySecretStore {
    fn get(
        &self,
        profile_name: &str,
        auth_type: AuthType,
    ) -> Result<Option<Secret>, SecretStoreError> {
        let mut toml_table = get_toml_table(&self.path)?;
        let Some(profile_table) = toml_table.remove(profile_name) else {
            return Ok(None);
        };
        let toml::Value::Table(mut profile_table) = profile_table else {
            return Ok(None);
        };

        Ok(Some(match auth_type {
            AuthType::ApiKeys => {
                let Some(public_api_key) =
                    try_get_optional_string(&mut profile_table, "public_api_key")?
                        .map(|s| s.to_string())
                else {
                    return Ok(None);
                };

                let Some(private_api_key) =
                    try_get_optional_string(&mut profile_table, "private_api_key")?
                        .map(|s| s.to_string())
                else {
                    return Ok(None);
                };

                Secret::ApiKeys(ApiKeys::new(public_api_key, private_api_key))
            }
            AuthType::ServiceAccount => {
                let Some(client_id) = try_get_optional_string(&mut profile_table, "client_id")?
                    .map(|s| s.to_string())
                else {
                    return Ok(None);
                };

                let Some(client_secret) =
                    try_get_optional_string(&mut profile_table, "client_secret")?
                        .map(|s| s.to_string())
                else {
                    return Ok(None);
                };

                let access_token =
                    try_get_optional_string(&mut profile_table, "service_account_access_token")?
                        .map(|s| s.to_string());

                let token_expires_at = try_get_optional_string(
                    &mut profile_table,
                    "service_account_token_expires_at",
                )?
                .and_then(|s| s.parse::<u64>().ok());

                Secret::ServiceAccount(ServiceAccount {
                    client_id,
                    client_secret,
                    access_token,
                    token_expires_at,
                })
            }
            AuthType::UserAccount => {
                let Some(access_token) =
                    try_get_optional_string(&mut profile_table, "access_token")?
                        .map(|s| s.to_string())
                else {
                    return Ok(None);
                };

                let Some(refresh_token) =
                    try_get_optional_string(&mut profile_table, "refresh_token")?
                        .map(|s| s.to_string())
                else {
                    return Ok(None);
                };
                Secret::UserAccount(UserAccount::new(access_token, refresh_token))
            }
        }))
    }

    fn set(&mut self, profile_name: &str, secret: Secret) -> Result<(), SecretStoreError> {
        let mut toml_table = get_toml_table(&self.path)?;
        let mut profile_table = toml_table
            .entry(profile_name)
            .or_insert(toml::Value::Table(Table::new()));
        let toml::Value::Table(profile_table) = &mut profile_table else {
            return Ok(());
        };

        match secret {
            Secret::ApiKeys(api_keys) => {
                profile_table.insert("public_api_key".to_string(), api_keys.public_api_key.into());
                profile_table.insert(
                    "private_api_key".to_string(),
                    api_keys.private_api_key.into(),
                );
            }
            Secret::ServiceAccount(service_account) => {
                profile_table.insert("client_id".to_string(), service_account.client_id.into());
                profile_table.insert(
                    "client_secret".to_string(),
                    service_account.client_secret.into(),
                );
                match service_account.access_token {
                    Some(token) => {
                        profile_table
                            .insert("service_account_access_token".to_string(), token.into());
                    }
                    None => {
                        profile_table.remove("service_account_access_token");
                    }
                }
                match service_account.token_expires_at {
                    Some(expires_at) => {
                        profile_table.insert(
                            "service_account_token_expires_at".to_string(),
                            expires_at.to_string().into(),
                        );
                    }
                    None => {
                        profile_table.remove("service_account_token_expires_at");
                    }
                }
            }
            Secret::UserAccount(user_account) => {
                profile_table.insert("access_token".to_string(), user_account.access_token.into());
                profile_table.insert(
                    "refresh_token".to_string(),
                    user_account.refresh_token.into(),
                );
            }
        }

        save_toml_table(&self.path, toml_table)?;

        Ok(())
    }

    fn delete(&mut self, profile_name: &str) -> Result<(), SecretStoreError> {
        let mut toml_table = get_toml_table(&self.path)?;
        toml_table.remove(profile_name);
        save_toml_table(&self.path, toml_table)?;
        Ok(())
    }
}

fn get_toml_table(path: impl AsRef<Path>) -> Result<Table, SecretStoreError> {
    let file_content = read_to_string(path).map_err(|e| SecretStoreError::KeyStoreUnavailable {
        reason: e.to_string(),
    })?;
    let toml: Table =
        toml::from_str(&file_content).map_err(|e| SecretStoreError::InvalidKeyStoreFormat {
            reason: e.to_string(),
        })?;

    Ok(toml)
}

fn try_get_optional_string<'a>(
    table: &'a mut Table,
    key: &'static str,
) -> Result<Option<&'a mut String>, SecretStoreError> {
    // Remove the key from the table
    let Some(value) = table.get_mut(key) else {
        return Ok(None);
    };

    // Convert the value to a string
    let Value::String(value) = value else {
        return Err(SecretStoreError::InvalidKeyStoreFormat {
            reason: format!("Key {} is not a string", key),
        });
    };

    // Return the value
    Ok(Some(value))
}

fn save_toml_table(path: impl AsRef<Path>, table: Table) -> Result<(), SecretStoreError> {
    let file_content = toml::to_string(&table).map_err(|e| SecretStoreError::Serialization {
        reason: e.to_string(),
    })?;
    std::fs::write(path, file_content).map_err(|e| SecretStoreError::KeyStoreUnavailable {
        reason: e.to_string(),
    })?;

    Ok(())
}
