use std::{
    fmt,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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
    #[error("Secret too large for the key store: {actual} bytes, max {max}")]
    SecretTooLarge { actual: usize, max: usize },
}

/// Trait for reading and writing authentication secrets.
///
/// The `Send + Sync` supertraits are required because the authentication
/// middleware stores the secret store behind an `Arc<RwLock<...>>`, which
/// requires `Send + Sync` for safe sharing across async tasks.
///
/// The `#[cfg_attr(test, mockall::automock)]` attribute generates a
/// `MockSecretStore` type during test compilation for use in unit tests.
#[cfg_attr(test, mockall::automock)]
pub trait SecretStore: Send + Sync {
    fn get(
        &self,
        profile_name: &ProfileName,
        auth_type: AuthType,
    ) -> Result<Option<Secret>, SecretStoreError>;
    fn set(&mut self, profile_name: &ProfileName, secret: Secret) -> Result<(), SecretStoreError>;
    fn delete(&mut self, profile_name: &ProfileName) -> Result<(), SecretStoreError>;
}

pub fn get_secret_store() -> Result<Box<dyn SecretStore>, SecretStoreError> {
    match KeyringSecretStore::new() {
        Some(keyring_secret_store) => Ok(Box::new(keyring_secret_store) as Box<dyn SecretStore>),
        None => Ok(Box::new(LegacySecretStore::new(config_file()?))),
    }
}

/// A CLI profile name, validated once so every store can rely on it.
///
/// The derived keychain service name (`atlascli_<profile>`) is fed to
/// `security -i` on macOS, which splits its input into commands on line
/// breaks, so those are rejected here instead of deep inside a backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProfileName(String);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid profile name {0:?}: must not be empty or contain line breaks")]
pub struct InvalidProfileName(String);

impl ProfileName {
    pub fn new(name: impl Into<String>) -> Result<Self, InvalidProfileName> {
        let name = name.into();
        if name.is_empty() || name.contains(['\n', '\r']) {
            return Err(InvalidProfileName(name));
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ProfileName {
    type Err = InvalidProfileName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl fmt::Display for ProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for ProfileName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

/// The per-profile entries a [`Secret`] is split into when stored.
///
/// The names double as keyring account names and legacy TOML keys, shared
/// with the Go Atlas CLI, so they must not change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretKey {
    AccessToken,
    RefreshToken,
    PublicApiKey,
    PrivateApiKey,
    ClientId,
    ClientSecret,
    ServiceAccountAccessToken,
    ServiceAccountTokenExpiresAt,
}

impl SecretKey {
    // ponytail: hand-maintained list; `as_str` is the exhaustive match that
    // fails to compile when a variant is added, add it here too.
    pub(crate) const ALL: [SecretKey; 8] = [
        SecretKey::AccessToken,
        SecretKey::RefreshToken,
        SecretKey::PublicApiKey,
        SecretKey::PrivateApiKey,
        SecretKey::ClientId,
        SecretKey::ClientSecret,
        SecretKey::ServiceAccountAccessToken,
        SecretKey::ServiceAccountTokenExpiresAt,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SecretKey::AccessToken => "access_token",
            SecretKey::RefreshToken => "refresh_token",
            SecretKey::PublicApiKey => "public_api_key",
            SecretKey::PrivateApiKey => "private_api_key",
            SecretKey::ClientId => "client_id",
            SecretKey::ClientSecret => "client_secret",
            SecretKey::ServiceAccountAccessToken => "service_account_access_token",
            SecretKey::ServiceAccountTokenExpiresAt => "service_account_token_expires_at",
        }
    }
}

/// Seconds since the Unix epoch: an instant, as opposed to the OAuth
/// `expires_in` *duration* it is usually derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTimestamp(pub u64);

impl UnixTimestamp {
    /// `None` if `time` is before the Unix epoch.
    pub fn from_system_time(time: SystemTime) -> Option<Self> {
        time.duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| Self(d.as_secs()))
    }

    pub fn to_system_time(self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0)
    }
}

impl fmt::Display for UnixTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for UnixTimestamp {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

/// Placeholder for secret fields in `Debug` output so a stray `{:?}` never
/// leaks credentials into logs.
const REDACTED: &str = "[redacted]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Secret {
    ApiKeys(ApiKeys),
    ServiceAccount(ServiceAccount),
    UserAccount(UserAccount),
}

#[derive(Clone, PartialEq, Eq)]
pub struct ApiKeys {
    pub public_api_key: String,
    pub private_api_key: String,
}

impl ApiKeys {
    pub fn new(public_api_key: String, private_api_key: String) -> Self {
        Self {
            public_api_key,
            private_api_key,
        }
    }
}

impl fmt::Debug for ApiKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKeys")
            .field("public_api_key", &self.public_api_key)
            .field("private_api_key", &REDACTED)
            .finish()
    }
}

impl From<ApiKeys> for Secret {
    fn from(api_keys: ApiKeys) -> Self {
        Secret::ApiKeys(api_keys)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    pub client_id: String,
    pub client_secret: String,
    /// Cached access token. When present, the auth middleware uses it directly
    /// instead of making a token endpoint request on the first call.
    pub access_token: Option<String>,
    /// When the cached access token should be proactively refreshed (already
    /// has the 30-second buffer subtracted). `None` if no expiry is known.
    pub token_expires_at: Option<UnixTimestamp>,
}

impl ServiceAccount {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            access_token: None,
            token_expires_at: None,
        }
    }
}

impl fmt::Debug for ServiceAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccount")
            .field("client_id", &self.client_id)
            .field("client_secret", &REDACTED)
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| REDACTED),
            )
            .field("token_expires_at", &self.token_expires_at)
            .finish()
    }
}

impl From<ServiceAccount> for Secret {
    fn from(service_account: ServiceAccount) -> Self {
        Secret::ServiceAccount(service_account)
    }
}

#[derive(Clone, PartialEq, Eq)]
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

impl fmt::Debug for UserAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserAccount")
            .field("access_token", &REDACTED)
            .field("refresh_token", &REDACTED)
            .finish()
    }
}

impl From<UserAccount> for Secret {
    fn from(user_account: UserAccount) -> Self {
        Secret::UserAccount(user_account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_name_rejects_empty_and_line_breaks() {
        assert!(ProfileName::new("default").is_ok());
        assert!(ProfileName::new("my profile").is_ok());
        assert!(ProfileName::new("").is_err());
        assert!(ProfileName::new("a\nb").is_err());
        assert!(ProfileName::new("a\rb").is_err());
    }

    #[test]
    fn unix_timestamp_round_trips_through_string_and_system_time() {
        let ts = UnixTimestamp(1_700_000_000);
        assert_eq!(ts.to_string().parse::<UnixTimestamp>().unwrap(), ts);
        assert_eq!(
            UnixTimestamp::from_system_time(ts.to_system_time()),
            Some(ts)
        );
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let secrets = [
            Secret::ServiceAccount(ServiceAccount {
                client_id: "CLIENT".into(),
                client_secret: "S3CR3T".into(),
                access_token: Some("T0K3N".into()),
                token_expires_at: Some(UnixTimestamp(1)),
            }),
            Secret::ApiKeys(ApiKeys::new("PUBL1C".into(), "PR1V4T3".into())),
            Secret::UserAccount(UserAccount::new("T0K3N".into(), "R3FR3SH".into())),
        ];
        let out = format!("{secrets:?}");
        for shown in ["CLIENT", "PUBL1C", "UnixTimestamp(1)"] {
            assert!(out.contains(shown), "{out}");
        }
        for hidden in ["S3CR3T", "T0K3N", "PR1V4T3", "R3FR3SH"] {
            assert!(!out.contains(hidden), "{out}");
        }
    }
}
