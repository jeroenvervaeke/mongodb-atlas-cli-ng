#!/usr/bin/env bash
#
# CI: import a real code-signing identity into a dedicated keychain so the macOS
# cargo runner (scripts/codesign-and-run.sh) can sign builds non-interactively —
# no GUI trust dialog and no "Always Allow" click.
#
# The local setup script (setup-codesign-identity.sh) is interactive on purpose
# (it asks for your login password to trust a self-signed cert). That can't run
# on a headless GitHub Actions runner, so on CI you instead ship a pre-made
# certificate as an encrypted secret and import it with this script. Run it once
# early in a macOS job; afterwards `cargo run`/`cargo test`/`cargo bench` sign
# automatically because the runner finds the identity in the search list.
#
# Create the secret once, locally, from your code-signing certificate:
#
#     base64 -i certificate.p12 | pbcopy        # paste into the GH secret
#
# (Any code-signing .p12 works: a Developer ID Application cert, an internal-CA
# cert, or a self-signed one exported from scripts/setup-codesign-identity.sh.)
#
# Required environment (wire these from GitHub Actions secrets/vars):
#   ATLAS_CLI_SIGN_CERT_P12_BASE64    base64 of the .p12
#   ATLAS_CLI_SIGN_CERT_P12_PASSWORD  password the .p12 was exported with
#   ATLAS_CLI_SIGN_IDENTITY           identity to sign with; must match the cert
#                                     (its common name, e.g. "Developer ID
#                                     Application: Name (TEAMID)"). Defaults to
#                                     the local dev identity name, so set this
#                                     unless your cert's CN happens to match.
# Optional:
#   ATLAS_CLI_SIGN_KEYCHAIN           keychain file to create/use
#                                     (default: under RUNNER_TEMP/TMPDIR)
#   ATLAS_CLI_SIGN_KEYCHAIN_PASSWORD  password for that keychain (default: random)

set -euo pipefail

IDENTITY="${ATLAS_CLI_SIGN_IDENTITY:-MongoDB Atlas CLI NG Dev}"
P12_B64="${ATLAS_CLI_SIGN_CERT_P12_BASE64:-}"
P12_PASS="${ATLAS_CLI_SIGN_CERT_P12_PASSWORD:-}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Code signing only applies on macOS; nothing to do on $(uname -s)."
  exit 0
fi

if [[ -z "$P12_B64" ]]; then
  echo "error: ATLAS_CLI_SIGN_CERT_P12_BASE64 is empty — set it from your CI secret." >&2
  exit 1
fi

for tool in security codesign openssl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: '$tool' not found on PATH." >&2; exit 1; }
done

KEYCHAIN="${ATLAS_CLI_SIGN_KEYCHAIN:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/atlas-codesign.keychain-db}"
KC_PASS="${ATLAS_CLI_SIGN_KEYCHAIN_PASSWORD:-$(openssl rand -base64 24)}"

workdir="$(mktemp -d)"
# The decoded .p12 is private key material; shred it as soon as we're done.
cleanup() { rm -f "$workdir/cert.p12"; rmdir "$workdir" 2>/dev/null || true; }
trap cleanup EXIT

# Decode via openssl (portable): macOS's BSD `base64` spells decode `-D`, not
# `--decode`, and `-A` accepts the secret whether it's one line or wrapped.
printf '%s' "$P12_B64" | openssl base64 -d -A >"$workdir/cert.p12"

# Dedicated, unlocked keychain that won't auto-lock mid-job. Recreate it so
# re-runs start from a clean slate, then add it to the search list so
# find-identity/codesign (which the runner calls without naming a keychain) see
# the imported identity.
security delete-keychain "$KEYCHAIN" 2>/dev/null || true
security create-keychain -p "$KC_PASS" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KC_PASS" "$KEYCHAIN"
existing_keychains="$(security list-keychains -d user | tr -d '"')"
# shellcheck disable=SC2086 # intentional word-splitting of the keychain list
security list-keychains -d user -s "$KEYCHAIN" $existing_keychains

# Import the identity, authorise codesign/security to use the private key, then
# set the partition list so signing never pops a prompt — the headless
# equivalent of clicking "Always Allow", and the step CI setups usually miss.
security import "$workdir/cert.p12" -P "$P12_PASS" -k "$KEYCHAIN" \
  -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple:,codesign: \
  -s -k "$KC_PASS" "$KEYCHAIN" >/dev/null

if ! security find-identity -v -p codesigning "$KEYCHAIN" | grep -qF "$IDENTITY"; then
  echo "error: imported the certificate but found no valid code-signing identity" >&2
  echo "       matching \"$IDENTITY\". Set ATLAS_CLI_SIGN_IDENTITY to the cert's" >&2
  echo "       name, and make sure the cert chains to a trusted root (a self-signed" >&2
  echo "       cert must also be trusted for code signing). Identities present:" >&2
  security find-identity -v -p codesigning "$KEYCHAIN" >&2 || true
  exit 1
fi

echo "Code-signing identity \"$IDENTITY\" imported into $KEYCHAIN."
echo "cargo run/test/bench on this runner will now sign automatically."
