use crate::config::AuthType;

pub mod legacy;

#[derive(thiserror::Error, Debug)]
pub enum SecretStoreError {
    #[error("Key store unavailable: {reason}")]
    KeyStoreUnavailable { reason: String },
    #[error("Invalid key store format: {reason}")]
    InvalidKeyStoreFormat { reason: String },
    #[error("Failed to serialize key store: {reason}")]
    FailedToSerialize { reason: String },
}

pub trait SecretStore {
    fn get(
        &mut self,
        profile_name: &str,
        auth_type: AuthType,
    ) -> Result<Option<Secret>, SecretStoreError>;
    fn set(&mut self, profile_name: &str, secret: Secret) -> Result<(), SecretStoreError>;
    fn delete(&mut self, profile_name: &str) -> Result<(), SecretStoreError>;
}

pub fn get_secret_store() -> Result<Box<dyn SecretStore>, SecretStoreError> {
    todo!()
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
