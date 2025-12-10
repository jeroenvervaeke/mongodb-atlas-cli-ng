use crate::{
    config::AuthType,
    path::{GetCLICfgFilePathError, config_file},
    secrets::{keyring::KeyringSecretStore, legacy::LegacySecretStore},
};

pub mod encoding;
pub mod keyring;
pub mod legacy;

#[derive(thiserror::Error, Debug)]
pub enum SecretStoreError {
    #[error("Failed to get config file path: {0}")]
    FailedToGetConfigFilePath(#[from] GetCLICfgFilePathError),
    #[error("Key store unavailable: {reason}")]
    KeyStoreUnavailable { reason: String },
    #[error("Invalid key store format: {reason}")]
    InvalidKeyStoreFormat { reason: String },
    #[error("Failed to serialize key store: {reason}")]
    Serialization { reason: String },
}

pub trait SecretStore {
    fn get(
        &self,
        profile_name: &str,
        auth_type: AuthType,
    ) -> Result<Option<Secret>, SecretStoreError>;
    fn set(&mut self, profile_name: &str, secret: Secret) -> Result<(), SecretStoreError>;
    fn delete(&mut self, profile_name: &str) -> Result<(), SecretStoreError>;
}

pub fn get_secret_store() -> Result<Box<dyn SecretStore>, SecretStoreError> {
    match KeyringSecretStore::new() {
        Some(keyring_secret_store) => Ok(Box::new(keyring_secret_store) as Box<dyn SecretStore>),
        None => Ok(Box::new(LegacySecretStore::new(config_file()?))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Secret {
    ApiKeys(ApiKeys),
    ServiceAccount(ServiceAccount),
    UserAccount(UserAccount),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeys {
    pub private_api_key: String,
    pub public_api_key: String,
}

impl ApiKeys {
    pub fn new(public_api_key: String, private_api_key: String) -> Self {
        Self {
            public_api_key,
            private_api_key,
        }
    }
}

impl From<ApiKeys> for Secret {
    fn from(api_keys: ApiKeys) -> Self {
        Secret::ApiKeys(api_keys)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    pub client_id: String,
    pub client_secret: String,
}

impl ServiceAccount {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }
}

impl From<ServiceAccount> for Secret {
    fn from(service_account: ServiceAccount) -> Self {
        Secret::ServiceAccount(service_account)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAccount {
    pub access_token: String,
    pub refresh_token: String,
}

impl UserAccount {
    pub fn new(access_token: String, refresh_token: String) -> Self {
        Self {
            access_token,
            refresh_token,
        }
    }
}

impl From<UserAccount> for Secret {
    fn from(user_account: UserAccount) -> Self {
        Secret::UserAccount(user_account)
    }
}
