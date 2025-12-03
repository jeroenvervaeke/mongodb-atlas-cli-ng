use std::{fs::File, io::copy};
use tempfile::NamedTempFile;

use mongodb_atlas_cli::{
    config::AuthType,
    secrets::{
        ApiKeys, Secret, SecretStore, ServiceAccount, UserAccount, legacy::LegacySecretStore,
    },
};

mod helper;
use helper::fixture_path;

#[test]
fn legacy_store_get_user_account_profile() {
    let expected = Secret::UserAccount(UserAccount::new(
        "user_account-1234567890".to_string(),
        "user_account-0987654321".to_string(),
    ));

    let mut legacy_store = LegacySecretStore::new(fixture_path("05-all-credential-types.toml"));

    let actual = legacy_store
        .get("profile_with_user_account", AuthType::UserAccount)
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

    let mut legacy_store = LegacySecretStore::new(fixture_path("05-all-credential-types.toml"));

    let actual = legacy_store
        .get("profile_with_api_keys", AuthType::ApiKeys)
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

    let mut legacy_store = LegacySecretStore::new(fixture_path("05-all-credential-types.toml"));

    let actual = legacy_store
        .get("profile_with_service_account", AuthType::ServiceAccount)
        .expect("should be able to load config file")
        .expect("service account should be present");

    // Assert that the actual config is equal to the expected config
    assert_eq!(expected, actual);
}

#[test]
fn legacy_store_get_profile_not_found() {
    let mut legacy_store = LegacySecretStore::new(fixture_path("05-all-credential-types.toml"));

    assert!(
        legacy_store
            .get("profile_not_found", AuthType::UserAccount)
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
            "profile_with_user_account",
            Secret::UserAccount(UserAccount::new(
                updated_user_account.to_string(),
                updated_refresh_token.to_string(),
            )),
        )
        .expect("should be able to update user account profile");

    // Get the updated user account profile
    legacy_store
        .set(
            "profile_with_user_account",
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
        .get("profile_with_user_account", AuthType::UserAccount)
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
            "profile_with_api_keys",
            Secret::ApiKeys(ApiKeys::new(
                updated_public_api_key.to_string(),
                updated_private_api_key.to_string(),
            )),
        )
        .expect("should be able to update api keys profile");

    // Get the updated user account profile
    legacy_store
        .set(
            "profile_with_api_keys",
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
        .get("profile_with_api_keys", AuthType::ApiKeys)
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
            "profile_with_service_account",
            Secret::ServiceAccount(ServiceAccount::new(
                updated_client_id.to_string(),
                updated_client_secret.to_string(),
            )),
        )
        .expect("should be able to update service account profile");

    // Get the updated user account profile
    legacy_store
        .set(
            "profile_with_service_account",
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
        .get("profile_with_service_account", AuthType::ServiceAccount)
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
            "profile_inserted_user_account",
            Secret::UserAccount(UserAccount::new(
                inserted_user_account.to_string(),
                inserted_access_token.to_string(),
            )),
        )
        .expect("should be able to set new user account profile");

    // Get the updated user account profile
    legacy_store
        .set(
            "profile_inserted_user_account",
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
        .get("profile_inserted_user_account", AuthType::UserAccount)
        .expect("should be able to load config file")
        .expect("new user account should be present");

    // Assert that the actual config is equal to the expected config
    assert_eq!(expected, actual);
}
