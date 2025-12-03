use std::path::PathBuf;

use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum GetCLICfgHomeDirectoryError {
    #[error("Could not determine config directory")]
    CouldNotDetermineConfigDir,
}

/// Get the path to the config directory for the current platform
///
/// On macOS, this is `~/Library/Application Support/atlascli`
/// On Linux, this is `~/.config/atlascli`
/// On Windows, this is `%APPDATA%\atlascli`
pub fn home_directory() -> Result<PathBuf, GetCLICfgHomeDirectoryError> {
    // Get the config directory for the current platform
    let config_dir =
        dirs::config_dir().ok_or(GetCLICfgHomeDirectoryError::CouldNotDetermineConfigDir)?;

    // Join the config directory with "atlascli"
    // On macOS, this is ~/Library/Application Support/atlascli
    let cli_config_dir = config_dir.join("atlascli");

    // Return the path to the config directory
    Ok(cli_config_dir)
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum GetCLICfgFilePathError {
    #[error("Could not determine config directory")]
    CouldNotDetermineConfigDir {
        #[from]
        source: GetCLICfgHomeDirectoryError,
    },
}

/// Get the path to the config file for the current platform
///
/// On macOS, this is `~/Library/Application Support/atlascli/config.toml`
/// On Linux, this is `~/.config/atlascli/config.toml`
/// On Windows, this is `%APPDATA%\atlascli\config.toml`
pub fn config_file() -> Result<PathBuf, GetCLICfgFilePathError> {
    // Get the path to the config directory for the current platform
    let cli_config_dir = home_directory()?;

    // Join the config directory with "config.toml"
    // On macOS, this is ~/Library/Application Support/atlascli/config.toml
    let config_file_path = cli_config_dir.join("config.toml");

    // Return the path to the config file
    Ok(config_file_path)
}
