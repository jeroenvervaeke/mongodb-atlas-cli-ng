use keyring::Entry;

use super::{ApiKeys, Secret, SecretStore, SecretStoreError, ServiceAccount, UserAccount};
use crate::{
    config::AuthType,
    secrets::encoding::{decode_password, encode_password},
};

const KEY_USER_ACCOUNT_ACCESS_TOKEN: &str = "access_token";
const KEY_USER_ACCOUNT_REFRESH_TOKEN: &str = "refresh_token";
const KEY_API_KEYS_PUBLIC_API_KEY: &str = "public_api_key";
const KEY_API_KEYS_PRIVATE_API_KEY: &str = "private_api_key";
const KEY_SERVICE_ACCOUNT_CLIENT_ID: &str = "client_id";
const KEY_SERVICE_ACCOUNT_CLIENT_SECRET: &str = "client_secret";
const KEY_SERVICE_ACCOUNT_ACCESS_TOKEN: &str = "service_account_access_token";

pub struct KeyringSecretStore {}

impl KeyringSecretStore {
    pub fn new() -> Option<Self> {
        // Determine if the keyring is available by trying to access a dummy entry
        if keyring_entry("default", "dummy").is_ok() {
            Some(Self {})
        } else {
            None
        }
    }
}

fn build_service_name(profile_name: &str) -> String {
    format!("atlascli_{}", profile_name)
}

fn keyring_entry(profile_name: &str, property_name: &str) -> Result<Entry, SecretStoreError> {
    Entry::new(&build_service_name(profile_name), property_name).map_err(|e| {
        SecretStoreError::InvalidKeyStoreFormat {
            reason: e.to_string(),
        }
    })
}

fn get_keyring_value(
    profile_name: &str,
    property_name: &str,
) -> Result<Option<String>, SecretStoreError> {
    let entry = keyring_entry(profile_name, property_name)?;
    match entry.get_password() {
        Ok(value) => Ok(decode_password(value)?),
        Err(e) => match e {
            keyring::Error::NoEntry => Ok(None),
            e => Err(SecretStoreError::InvalidKeyStoreFormat {
                reason: e.to_string(),
            }),
        },
    }
}

fn try_delete_entry(profile_name: &str, property_name: &str) {
    if let Ok(entry) = keyring_entry(profile_name, property_name) {
        _ = entry.delete_credential();
    }
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
    let entry = keyring_entry(profile_name, property_name)?;
    entry
        .set_password(encode_password(value).as_ref())
        .map_err(|e| SecretStoreError::KeyStoreUnavailable {
            reason: e.to_string(),
        })
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
                Some(Secret::ServiceAccount(ServiceAccount {
                    client_id,
                    client_secret,
                    access_token,
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
                    set_keyring_value(
                        profile_name,
                        KEY_SERVICE_ACCOUNT_ACCESS_TOKEN,
                        token,
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
        try_delete_entry(profile_name, KEY_USER_ACCOUNT_ACCESS_TOKEN);
        try_delete_entry(profile_name, KEY_USER_ACCOUNT_REFRESH_TOKEN);
        try_delete_entry(profile_name, KEY_API_KEYS_PUBLIC_API_KEY);
        try_delete_entry(profile_name, KEY_API_KEYS_PRIVATE_API_KEY);
        try_delete_entry(profile_name, KEY_SERVICE_ACCOUNT_CLIENT_ID);
        try_delete_entry(profile_name, KEY_SERVICE_ACCOUNT_CLIENT_SECRET);
        try_delete_entry(profile_name, KEY_SERVICE_ACCOUNT_ACCESS_TOKEN);

        Ok(())
    }
}
