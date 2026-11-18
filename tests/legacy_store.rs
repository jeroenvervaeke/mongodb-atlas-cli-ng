use std::{fs::File, io::copy};
use tempfile::NamedTempFile;

use mongodb_atlas_cli::{
    config::{self, AuthType},
    https_url::HttpsUrl,
    secrets::{
        ApiKeys, ProfileName, Secret, SecretStore, ServiceAccount, UserAccount, UserAccountLegacy,
        UserAccountSession, auth_server::CachedAuthServerMetadata, legacy::LegacySecretStore,
    },
};

mod helper;
use helper::fixture_path;

fn profile(name: &str) -> ProfileName {
    ProfileName::new(name).unwrap()
}

/// The `auth_server_metadata` of `profile_with_user_account` in the fixture.
const FIXTURE_METADATA: &str = r#"{"metadata":{"issuer":"https://authorize.mongodb.com","authorization_endpoint":"https://authorize.mongodb.com/authorize","token_endpoint":"https://authorize.mongodb.com/token","revocation_endpoint":"https://authorize.mongodb.com/revoke","code_challenge_methods_supported":["S256"]},"cache_expiry":"2026-11-25T10:00:00Z"}"#;

fn fixture_session() -> UserAccountSession {
    UserAccountSession {
        token_expiry: Some("2026-11-18T10:00:00Z".parse().unwrap()),
        auth_server_issuer: Some(HttpsUrl::new("https://authorize.mongodb.com").unwrap()),
        auth_server_metadata: Some(
            serde_json::from_str::<Box<CachedAuthServerMetadata>>(FIXTURE_METADATA).unwrap(),
        ),
    }
}

#[test]
fn legacy_store_get_user_account_legacy_profile() {
    let expected = Secret::UserAccountLegacy(UserAccountLegacy::new(
        "user_account_legacy-1234567890".to_string(),
        "user_account_legacy-0987654321".to_string(),
    ));

    let legacy_store = LegacySecretStore::new(fixture_path("05-all-credential-types.toml"));

    let actual = legacy_store
        .get(
            &profile("profile_with_user_account_legacy"),
            AuthType::UserAccountLegacy,
        )
        .expect("should be able to load config file")
        .expect("tokens should be present");

    assert_eq!(expected, actual);
}

/// A token refresh stores new tokens and a new session. The rest of the
/// profile, and the config as a whole, must stay loadable.
#[test]
fn legacy_store_refreshed_user_account_round_trips() {
    let fixture_path = fixture_path("05-all-credential-types.toml");
    let temp_config_file = NamedTempFile::new().expect("should be able to create temp file");
    std::fs::copy(fixture_path, temp_config_file.path())
        .expect("should be able to copy fixture file to temp file");
    let mut legacy_store = LegacySecretStore::new(temp_config_file.path().to_path_buf());

    let refreshed = Secret::UserAccount(UserAccount {
        access_token: "refreshed-access-token".to_string(),
        refresh_token: "refreshed-refresh-token".to_string(),
        session: UserAccountSession {
            token_expiry: Some("2026-11-18T12:00:00Z".parse().unwrap()),
            ..fixture_session()
        },
    });

    legacy_store
        .set(&profile("profile_with_user_account"), refreshed.clone())
        .expect("should be able to update user account profile");

    let actual = legacy_store
        .get(&profile("profile_with_user_account"), AuthType::UserAccount)
        .expect("should be able to load config file")
        .expect("user account should be present");
    assert_eq!(refreshed, actual);

    let config = config::load_config_from_file(
        temp_config_file.path(),
        false,
        Some("profile_with_user_account"),
    )
    .expect("config should still load");
    assert_eq!(Some(AuthType::UserAccount), config.auth_type);
}

#[test]
fn legacy_store_get_user_account_profile() {
    let expected = Secret::UserAccount(UserAccount {
        access_token: "user_account-1234567890".to_string(),
        refresh_token: "user_account-0987654321".to_string(),
        session: fixture_session(),
    });

    let legacy_store = LegacySecretStore::new(fixture_path("05-all-credential-types.toml"));

    let actual = legacy_store
        .get(&profile("profile_with_user_account"), AuthType::UserAccount)
        .expect("should be able to load config file")
        .expect("tokens should be present");

    // Assert that the actual config is equal to the expected config
    assert_eq!(expected, actual);
}

#[test]
fn legacy_store_get_api_keys_profile() {
    let expected = Secret::ApiKeys(ApiKeys::new(
        "api_keys-1234567890".to_string(),
        "api_keys-0987654321".to_string(),
    ));

    let legacy_store = LegacySecretStore::new(fixture_path("05-all-credential-types.toml"));

    let actual = legacy_store
        .get(&profile("profile_with_api_keys"), AuthType::ApiKeys)
        .expect("should be able to load config file")
        .expect("api keys should be present");

    // Assert that the actual config is equal to the expected config
    assert_eq!(expected, actual);
}

#[test]
fn legacy_store_get_service_account_profile() {
    let expected = Secret::ServiceAccount(ServiceAccount::new(
        "service_account-1234567890".to_string(),
        "service_account-0987654321".to_string(),
    ));

    let legacy_store = LegacySecretStore::new(fixture_path("05-all-credential-types.toml"));

    let actual = legacy_store
        .get(
            &profile("profile_with_service_account"),
            AuthType::ServiceAccount,
        )
        .expect("should be able to load config file")
        .expect("service account should be present");

    // Assert that the actual config is equal to the expected config
    assert_eq!(expected, actual);
}

#[test]
fn legacy_store_get_profile_not_found() {
    let legacy_store = LegacySecretStore::new(fixture_path("05-all-credential-types.toml"));

    assert!(
        legacy_store
            .get(&profile("profile_not_found"), AuthType::UserAccount)
            .expect("should be able to load config file")
            .is_none()
    );
}

#[test]
fn legacy_store_update_user_account_profile() {
    // Copy the fixture file to a temp file
    let fixture_path = fixture_path("05-all-credential-types.toml");
    let mut fixture_file = File::open(fixture_path).expect("should be able to open fixture file");
    let mut new_temp_config_file =
        NamedTempFile::new().expect("should be able to create temp file");
    copy(&mut fixture_file, &mut new_temp_config_file)
        .expect("should be able to copy fixture file to temp file");

    // Get the path of the temp file
    let new_temp_config_file_path = new_temp_config_file.path().to_path_buf();

    // Create a new legacy store with the temp file
    let mut legacy_store = LegacySecretStore::new(new_temp_config_file_path);

    // Update the user account profile
    let updated_user_account = "user_account-updated-1234567890";
    let updated_refresh_token = "user_account-updated-0987654321";

    legacy_store
        .set(
            &profile("profile_with_user_account"),
            Secret::UserAccount(UserAccount::new(
                updated_user_account.to_string(),
                updated_refresh_token.to_string(),
            )),
        )
        .expect("should be able to update user account profile");

    // Get the updated user account profile
    legacy_store
        .set(
            &profile("profile_with_user_account"),
            Secret::UserAccount(UserAccount::new(
                updated_user_account.to_string(),
                updated_refresh_token.to_string(),
            )),
        )
        .expect("should be able to update user account profile");

    let expected = Secret::UserAccount(UserAccount::new(
        updated_user_account.to_string(),
        updated_refresh_token.to_string(),
    ));

    let actual = legacy_store
        .get(&profile("profile_with_user_account"), AuthType::UserAccount)
        .expect("should be able to load config file")
        .expect("user account should be present");

    // Assert that the actual config is equal to the expected config
    assert_eq!(expected, actual);
}

#[test]
fn legacy_store_update_api_keys_profile() {
    // Copy the fixture file to a temp file
    let fixture_path = fixture_path("05-all-credential-types.toml");
    let mut fixture_file = File::open(fixture_path).expect("should be able to open fixture file");
    let mut new_temp_config_file =
        NamedTempFile::new().expect("should be able to create temp file");
    copy(&mut fixture_file, &mut new_temp_config_file)
        .expect("should be able to copy fixture file to temp file");

    // Get the path of the temp file
    let new_temp_config_file_path = new_temp_config_file.path().to_path_buf();

    // Create a new legacy store with the temp file
    let mut legacy_store = LegacySecretStore::new(new_temp_config_file_path);

    // Update the user account profile
    let updated_public_api_key = "api_keys-updated-1234567890";
    let updated_private_api_key = "api_keys-updated-0987654321";

    legacy_store
        .set(
            &profile("profile_with_api_keys"),
            Secret::ApiKeys(ApiKeys::new(
                updated_public_api_key.to_string(),
                updated_private_api_key.to_string(),
            )),
        )
        .expect("should be able to update api keys profile");

    // Get the updated user account profile
    legacy_store
        .set(
            &profile("profile_with_api_keys"),
            Secret::ApiKeys(ApiKeys::new(
                updated_public_api_key.to_string(),
                updated_private_api_key.to_string(),
            )),
        )
        .expect("should be able to update api keys profile");

    let expected = Secret::ApiKeys(ApiKeys::new(
        updated_public_api_key.to_string(),
        updated_private_api_key.to_string(),
    ));

    let actual = legacy_store
        .get(&profile("profile_with_api_keys"), AuthType::ApiKeys)
        .expect("should be able to load config file")
        .expect("api keys should be present");

    // Assert that the actual config is equal to the expected config
    assert_eq!(expected, actual);
}

#[test]
fn legacy_store_update_service_account_profile() {
    // Copy the fixture file to a temp file
    let fixture_path = fixture_path("05-all-credential-types.toml");
    let mut fixture_file = File::open(fixture_path).expect("should be able to open fixture file");
    let mut new_temp_config_file =
        NamedTempFile::new().expect("should be able to create temp file");
    copy(&mut fixture_file, &mut new_temp_config_file)
        .expect("should be able to copy fixture file to temp file");

    // Get the path of the temp file
    let new_temp_config_file_path = new_temp_config_file.path().to_path_buf();

    // Create a new legacy store with the temp file
    let mut legacy_store = LegacySecretStore::new(new_temp_config_file_path);

    // Update the user account profile
    let updated_client_id = "service_account-updated-1234567890";
    let updated_client_secret = "service_account-updated-0987654321";

    legacy_store
        .set(
            &profile("profile_with_service_account"),
            Secret::ServiceAccount(ServiceAccount::new(
                updated_client_id.to_string(),
                updated_client_secret.to_string(),
            )),
        )
        .expect("should be able to update service account profile");

    // Get the updated user account profile
    legacy_store
        .set(
            &profile("profile_with_service_account"),
            Secret::ServiceAccount(ServiceAccount::new(
                updated_client_id.to_string(),
                updated_client_secret.to_string(),
            )),
        )
        .expect("should be able to update service account profile");

    let expected = Secret::ServiceAccount(ServiceAccount::new(
        updated_client_id.to_string(),
        updated_client_secret.to_string(),
    ));

    let actual = legacy_store
        .get(
            &profile("profile_with_service_account"),
            AuthType::ServiceAccount,
        )
        .expect("should be able to load config file")
        .expect("service account should be present");

    // Assert that the actual config is equal to the expected config
    assert_eq!(expected, actual);
}

#[test]
fn legacy_store_set_new_profile() {
    // Copy the fixture file to a temp file
    let fixture_path = fixture_path("05-all-credential-types.toml");
    let mut fixture_file = File::open(fixture_path).expect("should be able to open fixture file");
    let mut new_temp_config_file =
        NamedTempFile::new().expect("should be able to create temp file");
    copy(&mut fixture_file, &mut new_temp_config_file)
        .expect("should be able to copy fixture file to temp file");

    // Get the path of the temp file
    let new_temp_config_file_path = new_temp_config_file.path().to_path_buf();

    // Create a new legacy store with the temp file
    let mut legacy_store = LegacySecretStore::new(new_temp_config_file_path);

    // Update the user account profile
    let inserted_user_account = "user_account-inserted-1234567890";
    let inserted_access_token = "user_account-inserted-0987654321";

    legacy_store
        .set(
            &profile("profile_inserted_user_account"),
            Secret::UserAccount(UserAccount::new(
                inserted_user_account.to_string(),
                inserted_access_token.to_string(),
            )),
        )
        .expect("should be able to set new user account profile");

    // Get the updated user account profile
    legacy_store
        .set(
            &profile("profile_inserted_user_account"),
            Secret::UserAccount(UserAccount::new(
                inserted_user_account.to_string(),
                inserted_access_token.to_string(),
            )),
        )
        .expect("should be able to set new user account profile");

    let expected = Secret::UserAccount(UserAccount::new(
        inserted_user_account.to_string(),
        inserted_access_token.to_string(),
    ));

    let actual = legacy_store
        .get(
            &profile("profile_inserted_user_account"),
            AuthType::UserAccount,
        )
        .expect("should be able to load config file")
        .expect("new user account should be present");

    // Assert that the actual config is equal to the expected config
    assert_eq!(expected, actual);
}
