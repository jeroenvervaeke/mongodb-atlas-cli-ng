use tracing::warn;

use super::{
    ApiKeys, ProfileName, Secret, SecretKey, SecretStore, SecretStoreError, ServiceAccount,
    UserAccount,
};
use crate::{
    config::AuthType,
    secrets::encoding::{decode_password, encode_password},
};

// Also compiled under `test` so its pure parsing/quoting tests run on every OS.
#[cfg(any(target_os = "macos", test))]
mod security_cli;
#[cfg(target_os = "macos")]
use security_cli as backend;

#[cfg(not(target_os = "macos"))]
mod keyring_crate;
#[cfg(not(target_os = "macos"))]
use keyring_crate as backend;

// Same probe the Go Atlas CLI's secure store uses to decide between the
// keyring and the config file.
const PROBE_PROFILE: &str = "default";
const PROBE_PROPERTY: &str = "test";

/// Keychain service name shared with the Go Atlas CLI: `atlascli_<profile>`.
pub(crate) struct KeychainService(String);

impl KeychainService {
    pub(crate) fn for_profile(profile_name: &ProfileName) -> Self {
        Self::new(profile_name.as_str())
    }

    fn new(profile_name: &str) -> Self {
        Self(format!("atlascli_{profile_name}"))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub struct KeyringSecretStore {}

impl KeyringSecretStore {
    pub fn new() -> Option<Self> {
        if backend::is_available(&KeychainService::new(PROBE_PROFILE), PROBE_PROPERTY) {
            Some(Self {})
        } else {
            None
        }
    }
}

fn get_keyring_value(
    profile_name: &ProfileName,
    key: SecretKey,
) -> Result<Option<String>, SecretStoreError> {
    match backend::get(&KeychainService::for_profile(profile_name), key.as_str())? {
        Some(value) => Ok(decode_password(value)?),
        None => Ok(None),
    }
}

fn delete_keyring_value(
    profile_name: &ProfileName,
    key: SecretKey,
) -> Result<(), SecretStoreError> {
    backend::delete(&KeychainService::for_profile(profile_name), key.as_str())
}

fn get_base_secret<S: Into<Secret>>(
    profile_name: &ProfileName,
    key_1: SecretKey,
    key_2: SecretKey,
    constructor: impl FnOnce(String, String) -> S,
) -> Result<Option<Secret>, SecretStoreError> {
    let Some(value_1) = get_keyring_value(profile_name, key_1)? else {
        return Ok(None);
    };
    let Some(value_2) = get_keyring_value(profile_name, key_2)? else {
        return Ok(None);
    };
    Ok(Some(constructor(value_1, value_2).into()))
}

fn set_keyring_value(
    profile_name: &ProfileName,
    key: SecretKey,
    value: &str,
) -> Result<(), SecretStoreError> {
    backend::set(
        &KeychainService::for_profile(profile_name),
        key.as_str(),
        &encode_password(value),
    )
}

impl SecretStore for KeyringSecretStore {
    fn get(
        &self,
        profile_name: &ProfileName,
        auth_type: AuthType,
    ) -> Result<Option<Secret>, SecretStoreError> {
        Ok(match auth_type {
            AuthType::UserAccount => get_base_secret(
                profile_name,
                SecretKey::AccessToken,
                SecretKey::RefreshToken,
                UserAccount::new,
            )?,
            AuthType::ApiKeys => get_base_secret(
                profile_name,
                SecretKey::PublicApiKey,
                SecretKey::PrivateApiKey,
                ApiKeys::new,
            )?,
            AuthType::ServiceAccount => {
                let Some(client_id) = get_keyring_value(profile_name, SecretKey::ClientId)? else {
                    return Ok(None);
                };
                let Some(client_secret) = get_keyring_value(profile_name, SecretKey::ClientSecret)?
                else {
                    return Ok(None);
                };
                let access_token =
                    get_keyring_value(profile_name, SecretKey::ServiceAccountAccessToken)?;
                let token_expires_at =
                    get_keyring_value(profile_name, SecretKey::ServiceAccountTokenExpiresAt)?
                        .and_then(|s| s.parse().ok());
                Some(Secret::ServiceAccount(ServiceAccount {
                    client_id,
                    client_secret,
                    access_token,
                    token_expires_at,
                }))
            }
        })
    }

    fn set(&mut self, profile_name: &ProfileName, secret: Secret) -> Result<(), SecretStoreError> {
        match secret {
            Secret::ApiKeys(api_keys) => {
                set_keyring_value(
                    profile_name,
                    SecretKey::PublicApiKey,
                    &api_keys.public_api_key,
                )?;
                set_keyring_value(
                    profile_name,
                    SecretKey::PrivateApiKey,
                    &api_keys.private_api_key,
                )?;
                Ok(())
            }
            Secret::ServiceAccount(service_account) => {
                // Clear stale cached-token keys before writing the new client
                // credentials: if a delete fails midway we must not leave a fresh
                // client_id paired with the previous account's access token.
                if service_account.access_token.is_none() {
                    delete_keyring_value(profile_name, SecretKey::ServiceAccountAccessToken)?;
                }
                if service_account.token_expires_at.is_none() {
                    delete_keyring_value(profile_name, SecretKey::ServiceAccountTokenExpiresAt)?;
                }
                set_keyring_value(
                    profile_name,
                    SecretKey::ClientId,
                    &service_account.client_id,
                )?;
                set_keyring_value(
                    profile_name,
                    SecretKey::ClientSecret,
                    &service_account.client_secret,
                )?;
                if let Some(token) = &service_account.access_token {
                    set_keyring_value(profile_name, SecretKey::ServiceAccountAccessToken, token)?;
                }
                if let Some(expires_at) = service_account.token_expires_at {
                    set_keyring_value(
                        profile_name,
                        SecretKey::ServiceAccountTokenExpiresAt,
                        &expires_at.to_string(),
                    )?;
                }
                Ok(())
            }
            Secret::UserAccount(user_account) => {
                set_keyring_value(
                    profile_name,
                    SecretKey::AccessToken,
                    &user_account.access_token,
                )?;
                set_keyring_value(
                    profile_name,
                    SecretKey::RefreshToken,
                    &user_account.refresh_token,
                )?;
                Ok(())
            }
        }
    }

    fn delete(&mut self, profile_name: &ProfileName) -> Result<(), SecretStoreError> {
        // Attempt every key so one failure doesn't leave the rest behind.
        let mut first_error = None;
        for key in SecretKey::ALL {
            if let Err(e) = delete_keyring_value(profile_name, key) {
                warn!(key = key.as_str(), error = %e, "failed to delete keyring entry");
                first_error.get_or_insert(e);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keychain_service_matches_go_atlas_cli_naming() {
        let service = KeychainService::for_profile(&ProfileName::new("default").unwrap());
        assert_eq!(service.as_str(), "atlascli_default");
    }
}
