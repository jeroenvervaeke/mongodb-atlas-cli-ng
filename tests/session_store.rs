use mongodb_atlas_cli::config::{
    self, AuthType, ConfigFileSessionStore, UserAccountSession, UserAccountSessionStore,
};
use pretty_assertions::assert_eq;
use tempfile::NamedTempFile;

mod helper;
use helper::fixture_path;

const PROFILE: &str = "profile_with_user_account";

fn temp_config() -> NamedTempFile {
    let temp_config_file = NamedTempFile::new().expect("should be able to create temp file");
    std::fs::copy(
        fixture_path("05-all-credential-types.toml"),
        temp_config_file.path(),
    )
    .expect("should be able to copy fixture file to temp file");
    temp_config_file
}

fn load(config_file: &NamedTempFile) -> config::AtlasCLIConfig {
    config::load_config_from_file(config_file.path(), false, Some(PROFILE))
        .expect("should be able to load config file")
}

/// What a token refresh saves is what the next config load reads, and the
/// rest of the profile is left alone.
#[test]
fn saved_session_is_read_back_by_load_config() {
    let config_file = temp_config();
    let before = load(&config_file);
    let refreshed = UserAccountSession {
        token_expiry: Some("2026-11-18T12:00:00Z".parse().unwrap()),
        ..before.user_account_session.clone()
    };

    ConfigFileSessionStore::new(config_file.path(), PROFILE)
        .save(&refreshed)
        .expect("should be able to save the session");

    let expected = config::AtlasCLIConfig {
        user_account_session: refreshed,
        ..before
    };
    assert_eq!(expected, load(&config_file));
    assert_eq!(Some(AuthType::UserAccount), expected.auth_type);
}

#[test]
fn saving_an_empty_session_removes_it_from_the_profile() {
    let config_file = temp_config();

    ConfigFileSessionStore::new(config_file.path(), PROFILE)
        .save(&UserAccountSession::default())
        .expect("should be able to save the session");

    assert_eq!(
        UserAccountSession::default(),
        load(&config_file).user_account_session
    );
    let content = std::fs::read_to_string(config_file.path()).unwrap();
    assert!(!content.contains("token_expiry"), "{content}");
}
