use tracing::warn;

use super::{ApiKeys, Secret, SecretStore, SecretStoreError, ServiceAccount, UserAccount};
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

const KEY_USER_ACCOUNT_ACCESS_TOKEN: &str = "access_token";
const KEY_USER_ACCOUNT_REFRESH_TOKEN: &str = "refresh_token";
const KEY_API_KEYS_PUBLIC_API_KEY: &str = "public_api_key";
const KEY_API_KEYS_PRIVATE_API_KEY: &str = "private_api_key";
const KEY_SERVICE_ACCOUNT_CLIENT_ID: &str = "client_id";
const KEY_SERVICE_ACCOUNT_CLIENT_SECRET: &str = "client_secret";
const KEY_SERVICE_ACCOUNT_ACCESS_TOKEN: &str = "service_account_access_token";
const KEY_SERVICE_ACCOUNT_TOKEN_EXPIRES_AT: &str = "service_account_token_expires_at";

// Same probe the Go Atlas CLI's secure store uses to decide between the
// keyring and the config file.
const PROBE_PROFILE: &str = "default";
const PROBE_PROPERTY: &str = "test";

pub struct KeyringSecretStore {}

impl KeyringSecretStore {
    pub fn new() -> Option<Self> {
        if backend::is_available(&build_service_name(PROBE_PROFILE), PROBE_PROPERTY) {
            Some(Self {})
        } else {
            None
        }
    }
}

fn build_service_name(profile_name: &str) -> String {
    format!("atlascli_{}", profile_name)
}

fn get_keyring_value(
    profile_name: &str,
    property_name: &str,
) -> Result<Option<String>, SecretStoreError> {
    match backend::get(&build_service_name(profile_name), property_name)? {
        Some(value) => Ok(decode_password(value)?),
        None => Ok(None),
    }
}

fn delete_keyring_value(profile_name: &str, property_name: &str) -> Result<(), SecretStoreError> {
    backend::delete(&build_service_name(profile_name), property_name)
}

fn get_base_secret<S: Into<Secret>>(
    profile_name: &str,
    property_1: &str,
    property_2: &str,
    constructor: impl FnOnce(String, String) -> S,
) -> Result<Option<Secret>, SecretStoreError> {
    let Some(value_1) = get_keyring_value(profile_name, property_1)? else {
        return Ok(None);
    };
    let Some(value_2) = get_keyring_value(profile_name, property_2)? else {
        return Ok(None);
    };
    Ok(Some(constructor(value_1, value_2).into()))
}

fn set_keyring_value(
    profile_name: &str,
    property_name: &str,
    value: &str,
) -> Result<(), SecretStoreError> {
    backend::set(
        &build_service_name(profile_name),
        property_name,
        encode_password(value).as_ref(),
    )
}

impl SecretStore for KeyringSecretStore {
    fn get(
        &self,
        profile_name: &str,
        auth_type: AuthType,
    ) -> Result<Option<Secret>, SecretStoreError> {
        Ok(match auth_type {
            AuthType::UserAccount => get_base_secret(
                profile_name,
                KEY_USER_ACCOUNT_ACCESS_TOKEN,
                KEY_USER_ACCOUNT_REFRESH_TOKEN,
                UserAccount::new,
            )?,
            AuthType::ApiKeys => get_base_secret(
                profile_name,
                KEY_API_KEYS_PUBLIC_API_KEY,
                KEY_API_KEYS_PRIVATE_API_KEY,
                ApiKeys::new,
            )?,
            AuthType::ServiceAccount => {
                let Some(client_id) =
                    get_keyring_value(profile_name, KEY_SERVICE_ACCOUNT_CLIENT_ID)?
                else {
                    return Ok(None);
                };
                let Some(client_secret) =
                    get_keyring_value(profile_name, KEY_SERVICE_ACCOUNT_CLIENT_SECRET)?
                else {
                    return Ok(None);
                };
                let access_token =
                    get_keyring_value(profile_name, KEY_SERVICE_ACCOUNT_ACCESS_TOKEN)?;
                let token_expires_at =
                    get_keyring_value(profile_name, KEY_SERVICE_ACCOUNT_TOKEN_EXPIRES_AT)?
                        .and_then(|s| s.parse::<u64>().ok());
                Some(Secret::ServiceAccount(ServiceAccount {
                    client_id,
                    client_secret,
                    access_token,
                    token_expires_at,
                }))
            }
        })
    }

    fn set(&mut self, profile_name: &str, secret: Secret) -> Result<(), SecretStoreError> {
        match secret {
            Secret::ApiKeys(api_keys) => {
                set_keyring_value(
                    profile_name,
                    KEY_API_KEYS_PUBLIC_API_KEY,
                    &api_keys.public_api_key,
                )?;
                set_keyring_value(
                    profile_name,
                    KEY_API_KEYS_PRIVATE_API_KEY,
                    &api_keys.private_api_key,
                )?;
                Ok(())
            }
            Secret::ServiceAccount(service_account) => {
                // Clear stale cached-token keys before writing the new client
                // credentials: if a delete fails midway we must not leave a fresh
                // client_id paired with the previous account's access token.
                if service_account.access_token.is_none() {
                    delete_keyring_value(profile_name, KEY_SERVICE_ACCOUNT_ACCESS_TOKEN)?;
                }
                if service_account.token_expires_at.is_none() {
                    delete_keyring_value(profile_name, KEY_SERVICE_ACCOUNT_TOKEN_EXPIRES_AT)?;
                }
                set_keyring_value(
                    profile_name,
                    KEY_SERVICE_ACCOUNT_CLIENT_ID,
                    &service_account.client_id,
                )?;
                set_keyring_value(
                    profile_name,
                    KEY_SERVICE_ACCOUNT_CLIENT_SECRET,
                    &service_account.client_secret,
                )?;
                if let Some(token) = &service_account.access_token {
                    set_keyring_value(profile_name, KEY_SERVICE_ACCOUNT_ACCESS_TOKEN, token)?;
                }
                if let Some(expires_at) = service_account.token_expires_at {
                    set_keyring_value(
                        profile_name,
                        KEY_SERVICE_ACCOUNT_TOKEN_EXPIRES_AT,
                        &expires_at.to_string(),
                    )?;
                }
                Ok(())
            }
            Secret::UserAccount(user_account) => {
                set_keyring_value(
                    profile_name,
                    KEY_USER_ACCOUNT_ACCESS_TOKEN,
                    &user_account.access_token,
                )?;
                set_keyring_value(
                    profile_name,
                    KEY_USER_ACCOUNT_REFRESH_TOKEN,
                    &user_account.refresh_token,
                )?;
                Ok(())
            }
        }
    }

    fn delete(&mut self, profile_name: &str) -> Result<(), SecretStoreError> {
        // Attempt every key so one failure doesn't leave the rest behind.
        let mut first_error = None;
        for property_name in [
            KEY_USER_ACCOUNT_ACCESS_TOKEN,
            KEY_USER_ACCOUNT_REFRESH_TOKEN,
            KEY_API_KEYS_PUBLIC_API_KEY,
            KEY_API_KEYS_PRIVATE_API_KEY,
            KEY_SERVICE_ACCOUNT_CLIENT_ID,
            KEY_SERVICE_ACCOUNT_CLIENT_SECRET,
            KEY_SERVICE_ACCOUNT_ACCESS_TOKEN,
            KEY_SERVICE_ACCOUNT_TOKEN_EXPIRES_AT,
        ] {
            if let Err(e) = delete_keyring_value(profile_name, property_name) {
                warn!(property_name, error = %e, "failed to delete keyring entry");
                first_error.get_or_insert(e);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}
