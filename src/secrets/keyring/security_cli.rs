//! macOS secret store backend that drives `/usr/bin/security`, exactly like
//! zalando/go-keyring (used by the official Atlas CLI) does.
//!
//! Why not the native Security.framework API: the legacy keychain ACL trusts
//! the *application that created an item*. For an unsigned `cargo install`
//! binary that identity is the binary hash, so every rebuild re-prompts
//! "wants to access your confidential information". Items created through
//! `security` trust `/usr/bin/security` (Apple-signed, stable), so neither
//! this CLI nor the Go CLI ever re-prompts, and both share the same items.
//! The protected-data keychain is not an option yet: it needs a provisioning
//! profile (-34018 otherwise) and is invisible to the Go CLI. Tracked as
//! future work in https://github.com/jeroenvervaeke/mongodb-atlas-cli-ng/issues/50.

#[cfg(target_os = "macos")]
use std::io::Write;
use std::process::Output;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};

#[cfg(target_os = "macos")]
use crate::secrets::keyring::KeychainService;
use crate::secrets::{SecretStoreError, encoding::EncodedSecret};

#[cfg(target_os = "macos")]
const SECURITY_BIN: &str = "/usr/bin/security";
const NOT_FOUND_MARKER: &str = "could not be found";
// Same per-command limit go-keyring enforces for `security -i`; keeps behaviour identical.
const MAX_COMMAND_LEN: usize = 4096;

#[cfg(target_os = "macos")]
pub fn is_available(service: &KeychainService, account: &str) -> bool {
    // A missing item still proves `security` runs and can reach the keychain.
    get(service, account).is_ok()
}

#[cfg(target_os = "macos")]
pub fn get(
    service: &KeychainService,
    account: &str,
) -> Result<Option<EncodedSecret>, SecretStoreError> {
    let output = Command::new(SECURITY_BIN)
        .args([
            "find-generic-password",
            "-s",
            service.as_str(),
            "-wa",
            account,
        ])
        .output()
        .map_err(io_error)?;
    parse_find_output(&output)
}

#[cfg(target_os = "macos")]
pub fn set(
    service: &KeychainService,
    account: &str,
    value: &EncodedSecret,
) -> Result<(), SecretStoreError> {
    // Interactive mode keeps the secret out of argv (and thus out of `ps`).
    let command = build_add_command(service.as_str(), account, value.as_str())?;
    let mut child = Command::new(SECURITY_BIN)
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(io_error)?;
    let Some(mut stdin) = child.stdin.take() else {
        return Err(SecretStoreError::KeyStoreUnavailable {
            reason: format!("{SECURITY_BIN} did not expose a stdin pipe"),
        });
    };
    // Always reap the child, even when the write fails (EPIPE when `security`
    // exits early): otherwise it lingers as a zombie and its stderr, which is
    // the only explanation of what went wrong, is lost.
    let write_result = stdin.write_all(command.as_bytes());
    drop(stdin);
    let output = child.wait_with_output().map_err(io_error)?;
    if !output.status.success() {
        return Err(unavailable(&output));
    }
    write_result.map_err(io_error)
}

#[cfg(target_os = "macos")]
pub fn delete(service: &KeychainService, account: &str) -> Result<(), SecretStoreError> {
    let output = Command::new(SECURITY_BIN)
        .args([
            "delete-generic-password",
            "-s",
            service.as_str(),
            "-a",
            account,
        ])
        .output()
        .map_err(io_error)?;
    if output.status.success() || is_not_found(&output) {
        Ok(())
    } else {
        Err(unavailable(&output))
    }
}

fn parse_find_output(output: &Output) -> Result<Option<EncodedSecret>, SecretStoreError> {
    if is_not_found(output) {
        return Ok(None);
    }
    if !output.status.success() {
        return Err(unavailable(output));
    }
    // Strict decoding, matching the keyring-crate backend: a lossy conversion
    // would hand a silently mangled secret to the caller.
    let value = String::from_utf8(output.stdout.clone()).map_err(|e| {
        SecretStoreError::InvalidKeyStoreFormat {
            reason: format!("secret is not valid UTF-8: {e}"),
        }
    })?;
    Ok(Some(EncodedSecret(value.trim().to_string())))
}

fn build_add_command(
    service: &str,
    account: &str,
    value: &str,
) -> Result<String, SecretStoreError> {
    // `security -i` splits its input into commands on line breaks *before*
    // quote parsing, so single-quoting cannot neutralise an embedded newline:
    // it would terminate this command and run the remainder as a new one.
    if [service, account, value]
        .iter()
        .any(|s| contains_line_break(s))
    {
        return Err(SecretStoreError::InvalidKeyStoreFormat {
            reason: "service, account and secret must not contain line breaks".to_string(),
        });
    }
    let command = format!(
        "add-generic-password -U -s {} -a {} -w {}\n",
        quote(service),
        quote(account),
        quote(value)
    );
    if command.len() > MAX_COMMAND_LEN {
        return Err(SecretStoreError::SecretTooLarge {
            actual: command.len(),
            max: MAX_COMMAND_LEN,
        });
    }
    Ok(command)
}

fn contains_line_break(s: &str) -> bool {
    s.contains(['\n', '\r'])
}

/// Quote a token for `security -i`; mirrors go-keyring's shellescape.Quote.
fn quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    let is_safe = |c: char| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c);
    if s.chars().all(is_safe) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

fn is_not_found(output: &Output) -> bool {
    !output.status.success() && String::from_utf8_lossy(&output.stderr).contains(NOT_FOUND_MARKER)
}

fn unavailable(output: &Output) -> SecretStoreError {
    SecretStoreError::KeyStoreUnavailable {
        reason: format!(
            "security exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    }
}

#[cfg(target_os = "macos")]
fn io_error(e: std::io::Error) -> SecretStoreError {
    SecretStoreError::KeyStoreUnavailable {
        reason: format!("failed to run {SECURITY_BIN}: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use std::process::ExitStatus;

    use super::*;

    #[cfg(unix)]
    fn exit_status(code: i32) -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(code << 8)
    }

    #[cfg(windows)]
    fn exit_status(code: i32) -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(code as u32)
    }

    fn output(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status: exit_status(code),
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    #[test]
    fn test_parse_find_output_returns_trimmed_password() {
        let parsed = parse_find_output(&output(0, "go-keyring-base64:YWJj\n", "")).unwrap();
        assert_eq!(
            parsed,
            Some(EncodedSecret("go-keyring-base64:YWJj".to_string()))
        );
    }

    #[test]
    fn test_parse_find_output_returns_none_when_item_missing() {
        let stderr = "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n";
        let parsed = parse_find_output(&output(44, "", stderr)).unwrap();
        assert_eq!(parsed, None);
    }

    #[test]
    fn test_parse_find_output_returns_error_on_other_failure() {
        let err =
            parse_find_output(&output(51, "", "User interaction is not allowed.")).unwrap_err();
        assert!(
            matches!(err, SecretStoreError::KeyStoreUnavailable { reason } if reason.contains("User interaction"))
        );
    }

    #[test]
    fn test_parse_find_output_returns_empty_string_when_stdout_is_blank() {
        // `decode_password` turns "" into None downstream; this pins the contract it relies on.
        let parsed = parse_find_output(&output(0, "\n", "")).unwrap();
        assert_eq!(parsed, Some(EncodedSecret(String::new())));
    }

    #[test]
    fn test_parse_find_output_keeps_value_when_marker_appears_on_success() {
        let parsed = parse_find_output(&output(0, "secret\n", "could not be found")).unwrap();
        assert_eq!(parsed, Some(EncodedSecret("secret".to_string())));
    }

    #[test]
    fn test_parse_find_output_rejects_invalid_utf8() {
        let raw = Output {
            status: exit_status(0),
            stdout: vec![0xff, 0xfe, b'\n'],
            stderr: Vec::new(),
        };
        let err = parse_find_output(&raw).unwrap_err();
        assert!(
            matches!(err, SecretStoreError::InvalidKeyStoreFormat { reason } if reason.contains("UTF-8"))
        );
    }

    #[test]
    fn test_is_not_found_requires_failure_exit_status() {
        assert!(!is_not_found(&output(0, "", "could not be found")));
        assert!(is_not_found(&output(44, "", "could not be found")));
    }

    #[test]
    fn test_build_add_command_leaves_safe_tokens_unquoted() {
        let cmd = build_add_command("atlascli_default", "access_token", "go-keyring-base64:YWJj")
            .unwrap();
        assert_eq!(
            cmd,
            "add-generic-password -U -s atlascli_default -a access_token -w go-keyring-base64:YWJj\n"
        );
    }

    #[test]
    fn test_build_add_command_quotes_unsafe_tokens() {
        let cmd = build_add_command("atlascli_my profile", "it's", "a b").unwrap();
        assert_eq!(
            cmd,
            "add-generic-password -U -s 'atlascli_my profile' -a 'it'\"'\"'s' -w 'a b'\n"
        );
    }

    #[test]
    fn test_build_add_command_accepts_command_at_exact_limit() {
        let value = "x".repeat(padding_to_reach(MAX_COMMAND_LEN));
        let cmd = build_add_command("s", "a", &value).unwrap();
        assert_eq!(cmd.len(), MAX_COMMAND_LEN);
    }

    #[test]
    fn test_build_add_command_rejects_command_one_byte_over_limit() {
        let value = "x".repeat(padding_to_reach(MAX_COMMAND_LEN) + 1);
        let err = build_add_command("s", "a", &value).unwrap_err();
        assert!(matches!(
            err,
            SecretStoreError::SecretTooLarge { actual, max } if actual == MAX_COMMAND_LEN + 1 && max == MAX_COMMAND_LEN
        ));
    }

    #[test]
    fn test_build_add_command_rejects_newline_in_service() {
        let err =
            build_add_command("atlascli_a\ndelete-generic-password -s x", "a", "v").unwrap_err();
        assert!(
            matches!(err, SecretStoreError::InvalidKeyStoreFormat { reason } if reason.contains("line breaks"))
        );
    }

    #[test]
    fn test_build_add_command_rejects_carriage_return_in_value() {
        let err = build_add_command("s", "a", "v\r").unwrap_err();
        assert!(matches!(
            err,
            SecretStoreError::InvalidKeyStoreFormat { .. }
        ));
    }

    /// Number of `x` bytes that makes `build_add_command("s", "a", value)` exactly `target` long.
    fn padding_to_reach(target: usize) -> usize {
        let with_one_byte = build_add_command("s", "a", "x").unwrap().len();
        target - with_one_byte + 1
    }

    /// Runs against the real login keychain; pins the whole `security` interop
    /// contract (find/add/update/delete, exit codes, not-found detection).
    #[cfg(target_os = "macos")]
    #[test]
    fn test_round_trip_against_real_keychain() {
        use crate::secrets::ProfileName;
        let profile =
            ProfileName::new(format!("test-security-cli-{}", std::process::id())).unwrap();
        let service = KeychainService::for_profile(&profile);
        let account = "smoke";
        let abc = EncodedSecret("go-keyring-base64:YWJj".to_string());
        let xyz = EncodedSecret("go-keyring-base64:eHl6".to_string());

        assert_eq!(get(&service, account).unwrap(), None);
        assert!(is_available(&service, account));

        set(&service, account, &abc).unwrap();
        assert_eq!(get(&service, account).unwrap(), Some(abc));

        // `-U` must update in place rather than fail on the existing item.
        set(&service, account, &xyz).unwrap();
        assert_eq!(get(&service, account).unwrap(), Some(xyz));

        delete(&service, account).unwrap();
        assert_eq!(get(&service, account).unwrap(), None);
        delete(&service, account).unwrap();
    }

    /// `set` relies on `security -i` exiting non-zero when a command fails.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_interactive_mode_propagates_command_failure() {
        let mut child = Command::new(SECURITY_BIN)
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin
            .write_all(b"delete-generic-password -s atlascli_test-missing -a nope\n")
            .unwrap();
        drop(stdin);
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(is_not_found(&output));
    }

    #[test]
    fn test_quote_empty_string() {
        assert_eq!(quote(""), "''");
    }

    #[test]
    fn test_quote_leaves_entire_safe_charset_unquoted() {
        let safe = "abcXYZ019_@%+=:,./-";
        assert_eq!(quote(safe), safe);
    }

    #[test]
    fn test_quote_wraps_unsafe_characters() {
        for (input, expected) in [
            ("my profile", "'my profile'"),
            ("!lead", "'!lead'"),
            ("trail!", "'trail!'"),
            ("a\nb", "'a\nb'"),
            ("é", "'é'"),
        ] {
            assert_eq!(quote(input), expected, "input: {input:?}");
        }
    }

    #[test]
    fn test_quote_escapes_single_quotes_like_go_keyring() {
        assert_eq!(quote("it's"), "'it'\"'\"'s'");
    }
}
