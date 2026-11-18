use mongodb_atlas_cli::config;
use pretty_assertions::assert_eq;

mod helper;
use helper::fixture_path;

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
        ops_manager_url: None,
        client_id: None,
        auth_server_url: None,
        auth_client_id: None,
        user_account_session: config::UserAccountSession::default(),
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
fn user_account_session_is_read_from_the_profile() {
    let metadata = r#"{"metadata":{"issuer":"https://authorize.mongodb.com","authorization_endpoint":"https://authorize.mongodb.com/authorize","token_endpoint":"https://authorize.mongodb.com/token","revocation_endpoint":"https://authorize.mongodb.com/revoke","code_challenge_methods_supported":["S256"]},"cache_expiry":"2026-11-25T10:00:00Z"}"#;
    let expected = config::UserAccountSession {
        token_expiry: Some("2026-11-18T10:00:00Z".parse().unwrap()),
        auth_server_issuer: Some("https://authorize.mongodb.com".parse().unwrap()),
        auth_server_metadata: Some(metadata.parse().unwrap()),
    };

    let actual = config::load_config_from_file(
        fixture_path("05-all-credential-types.toml"),
        false,
        Some("profile_with_user_account"),
    )
    .expect("should be able to load config file");

    assert_eq!(expected, actual.user_account_session);
}

#[test]
fn all_options_config_profile_with_user_account_legacy() {
    let actual = config::load_config_from_file(
        fixture_path("03-all-options.toml"),
        false,
        Some("profile_with_user_account_legacy"),
    )
    .expect("should be able to load config file");

    assert_eq!(Some(config::AuthType::UserAccountLegacy), actual.auth_type);
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

#[test]
fn load_config_from_file_outdated_version() {
    let result =
        config::load_config_from_file(fixture_path("06-outdated-version.toml"), false, None);

    assert!(matches!(
        result,
        Err(config::LoadCLIConfigError::UnsupportedConfigVersion(2))
    ));
}
