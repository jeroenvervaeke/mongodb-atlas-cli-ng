use std::path::PathBuf;

use mongodb_atlas_cli::config;
use pretty_assertions::assert_eq;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn minimal_config() {
    let expected = config::AtlasCLIConfig::default();

    let actual = config::load_config_from_file(fixture_path("00-minimal.toml"), false, None)
        .expect("should be able to load config file");

    // Assert that the actual config is equal to the expected config
    assert_eq!(expected, actual);
}

#[test]
fn global_properties_config() {
    let expected = config::AtlasCLIConfig {
        local_deployment_image: Some(
            "my-registry.internal:5000/atlas-cli-local:latest".to_string(),
        ),
        mongosh_path: Some("/home/user/mdb-tools/mongosh".to_string()),
        telemetry_enabled: Some(true),
        skip_update_check: Some(true),
        ..Default::default()
    };

    let actual =
        config::load_config_from_file(fixture_path("01-global-properties.toml"), false, None)
            .expect("should be able to load config file");

    // Assert that the actual config is equal to the expected config
    assert_eq!(expected, actual);
}

#[test]
fn user_account_profile_config() {
    let expected = config::AtlasCLIConfig {
        skip_update_check: Some(true),
        auth_type: Some(config::AuthType::UserAccount),
        org_id: Some("689eeba6559f4608e426b000".to_string()),
        project_id: Some("689eebca5ebb720663a2d123".to_string()),
        service: Some(config::Service::Cloud),
        output: Some(config::OutputFormat::Json),
        ..Default::default()
    };

    let actual = config::load_config_from_file(
        fixture_path("02-user-account.toml"),
        false,
        Some("profile_1"),
    )
    .expect("should be able to load config file");

    // Assert that the actual config is equal to the expected config
    assert_eq!(expected, actual);
}

#[test]
fn all_options_config_profile_with_user_account() {
    let expected = config::AtlasCLIConfig {
        local_deployment_image: Some(
            "my-registry.internal:5000/atlas-cli-local:latest".to_string(),
        ),
        mongosh_path: Some("/home/user/mdb-tools/mongosh".to_string()),
        telemetry_enabled: Some(true),
        skip_update_check: Some(true),
        auth_type: Some(config::AuthType::UserAccount),
        org_id: Some("689eeba6559f4608e426b000".to_string()),
        project_id: Some("689eebca5ebb720663a2d123".to_string()),
        service: Some(config::Service::Cloud),
        output: Some(config::OutputFormat::Json),
    };

    let actual = config::load_config_from_file(
        fixture_path("03-all-options.toml"),
        false,
        Some("profile_with_user_account"),
    )
    .expect("should be able to load config file");

    // Assert that the actual config is equal to the expected config
    assert_eq!(expected, actual);
}

#[test]
fn all_options_config_profile_with_api_keys() {
    let expected = config::AtlasCLIConfig {
        local_deployment_image: Some(
            "my-registry.internal:5000/atlas-cli-local:latest".to_string(),
        ),
        mongosh_path: Some("/home/user/mdb-tools/mongosh".to_string()),
        telemetry_enabled: Some(true),
        skip_update_check: Some(true),
        auth_type: Some(config::AuthType::ApiKeys),
        ..Default::default()
    };

    let actual = config::load_config_from_file(
        fixture_path("03-all-options.toml"),
        false,
        Some("profile_with_api_keys"),
    )
    .expect("should be able to load config file");

    // Assert that the actual config is equal to the expected config
    assert_eq!(expected, actual);
}

#[test]
fn all_options_config_profile_with_service_account() {
    let expected = config::AtlasCLIConfig {
        local_deployment_image: Some(
            "my-registry.internal:5000/atlas-cli-local:latest".to_string(),
        ),
        mongosh_path: Some("/home/user/mdb-tools/mongosh".to_string()),
        telemetry_enabled: Some(true),
        skip_update_check: Some(true),
        auth_type: Some(config::AuthType::ServiceAccount),
        service: Some(config::Service::CloudGov),
        output: Some(config::OutputFormat::Plaintext),
        ..Default::default()
    };

    let actual = config::load_config_from_file(
        fixture_path("03-all-options.toml"),
        false,
        Some("profile_with_service_account"),
    )
    .expect("should be able to load config file");

    // Assert that the actual config is equal to the expected config
    assert_eq!(expected, actual);
}

#[test]
fn load_config_from_file_invalid_version() {
    let result =
        config::load_config_from_file(fixture_path("04-invalid-version.toml"), false, None);
    assert!(result.is_err());
}
