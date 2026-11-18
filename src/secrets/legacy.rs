use std::path::PathBuf;

use toml::{Table, Value};

use crate::{
    config::AuthType,
    secrets::{ApiKeys, ServiceAccount, UserAccount, UserAccountLegacy},
};

use super::{
    ProfileName, Secret, SecretKey, SecretStore, SecretStoreError,
    profile_file::{
        optional_string, profile_table_mut, read_table, read_user_account_session, save_table,
        write_user_account_session,
    },
};

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
        profile_name: &ProfileName,
        auth_type: AuthType,
    ) -> Result<Option<Secret>, SecretStoreError> {
        let toml_table = read_table(&self.path)?;
        let Some(Value::Table(profile_table)) = toml_table.get(profile_name.as_str()) else {
            return Ok(None);
        };

        Ok(match auth_type {
            AuthType::ApiKeys => string_pair(
                profile_table,
                SecretKey::PublicApiKey,
                SecretKey::PrivateApiKey,
            )?
            .map(|(public_api_key, private_api_key)| {
                Secret::ApiKeys(ApiKeys::new(public_api_key, private_api_key))
            }),
            AuthType::ServiceAccount => {
                let Some((client_id, client_secret)) =
                    string_pair(profile_table, SecretKey::ClientId, SecretKey::ClientSecret)?
                else {
                    return Ok(None);
                };

                Some(Secret::ServiceAccount(ServiceAccount {
                    client_id,
                    client_secret,
                    access_token: optional_string(
                        profile_table,
                        SecretKey::ServiceAccountAccessToken.as_str(),
                    )?,
                    token_expires_at: optional_string(
                        profile_table,
                        SecretKey::ServiceAccountTokenExpiresAt.as_str(),
                    )?
                    .and_then(|s| s.parse().ok()),
                }))
            }
            AuthType::UserAccount => {
                let Some((access_token, refresh_token)) = tokens(profile_table)? else {
                    return Ok(None);
                };

                Some(Secret::UserAccount(UserAccount {
                    access_token,
                    refresh_token,
                    session: read_user_account_session(profile_table)?,
                }))
            }
            AuthType::UserAccountLegacy => {
                tokens(profile_table)?.map(|(access_token, refresh_token)| {
                    Secret::UserAccountLegacy(UserAccountLegacy::new(access_token, refresh_token))
                })
            }
        })
    }

    fn set(&mut self, profile_name: &ProfileName, secret: Secret) -> Result<(), SecretStoreError> {
        let mut toml_table = read_table(&self.path)?;
        let profile_table = profile_table_mut(&mut toml_table, profile_name)?;

        match secret {
            Secret::ApiKeys(api_keys) => {
                profile_table.insert(
                    SecretKey::PublicApiKey.as_str().to_string(),
                    api_keys.public_api_key.into(),
                );
                profile_table.insert(
                    SecretKey::PrivateApiKey.as_str().to_string(),
                    api_keys.private_api_key.into(),
                );
            }
            Secret::ServiceAccount(service_account) => {
                profile_table.insert(
                    SecretKey::ClientId.as_str().to_string(),
                    service_account.client_id.into(),
                );
                profile_table.insert(
                    SecretKey::ClientSecret.as_str().to_string(),
                    service_account.client_secret.into(),
                );
                match service_account.access_token {
                    Some(token) => {
                        profile_table.insert(
                            SecretKey::ServiceAccountAccessToken.as_str().to_string(),
                            token.into(),
                        );
                    }
                    None => {
                        profile_table.remove(SecretKey::ServiceAccountAccessToken.as_str());
                    }
                }
                match service_account.token_expires_at {
                    Some(expires_at) => {
                        profile_table.insert(
                            SecretKey::ServiceAccountTokenExpiresAt.as_str().to_string(),
                            expires_at.to_string().into(),
                        );
                    }
                    None => {
                        profile_table.remove(SecretKey::ServiceAccountTokenExpiresAt.as_str());
                    }
                }
            }
            Secret::UserAccount(user_account) => {
                write_user_account_session(profile_table, &user_account.session)?;
                insert_tokens(
                    profile_table,
                    user_account.access_token,
                    user_account.refresh_token,
                );
            }
            Secret::UserAccountLegacy(user_account) => insert_tokens(
                profile_table,
                user_account.access_token,
                user_account.refresh_token,
            ),
        }

        save_table(&self.path, &toml_table)
    }

    fn delete(&mut self, profile_name: &ProfileName) -> Result<(), SecretStoreError> {
        let mut toml_table = read_table(&self.path)?;
        toml_table.remove(profile_name.as_str());
        save_table(&self.path, &toml_table)
    }
}

fn tokens(profile_table: &Table) -> Result<Option<(String, String)>, SecretStoreError> {
    string_pair(
        profile_table,
        SecretKey::AccessToken,
        SecretKey::RefreshToken,
    )
}

fn string_pair(
    table: &Table,
    key_1: SecretKey,
    key_2: SecretKey,
) -> Result<Option<(String, String)>, SecretStoreError> {
    let Some(value_1) = optional_string(table, key_1.as_str())? else {
        return Ok(None);
    };
    let Some(value_2) = optional_string(table, key_2.as_str())? else {
        return Ok(None);
    };
    Ok(Some((value_1, value_2)))
}

fn insert_tokens(profile_table: &mut Table, access_token: String, refresh_token: String) {
    profile_table.insert(
        SecretKey::AccessToken.as_str().to_string(),
        access_token.into(),
    );
    profile_table.insert(
        SecretKey::RefreshToken.as_str().to_string(),
        refresh_token.into(),
    );
}
