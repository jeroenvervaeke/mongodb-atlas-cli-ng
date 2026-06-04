#!/usr/bin/env bash
#
# Cargo target runner for macOS: codesign a freshly built binary with a stable,
# self-signed identity, then exec it.
#
# WHY THIS EXISTS
# ---------------
# macOS stores Keychain credentials with an access-control list (ACL) keyed off
# the *code signature* of the program that created/accessed the item. A normal
# `cargo run`/`cargo build` is ad-hoc signed, and an ad-hoc signature's
# "designated requirement" is the binary's content hash (cdhash). That hash
# changes on every rebuild, so the Keychain treats each rebuild as a brand-new,
# untrusted program and re-prompts:
#
#     "<binary> wants to use your confidential information stored in
#      "atlascli_default" in your keychain."
#
# Signing every build with the *same* certificate and the *same* bundle
# identifier keeps the designated requirement stable across rebuilds, so a
# single "Always Allow" survives future rebuilds and the prompts stop.
#
# See https://github.com/open-source-cooperative/keyring-rs/issues/272
#
# HOW IT'S WIRED
# --------------
# .cargo/config.toml registers this as the macOS target runner, so `cargo run
# --example ...` (and `cargo run`, `cargo test`) sign automatically. It is a
# safe no-op when no dev identity is installed (e.g. on CI or before the
# one-time setup), so it never blocks a build.
#
# Run scripts/setup-codesign-identity.sh once to create the identity.

set -euo pipefail

# Shared with scripts/setup-codesign-identity.sh. Override via the environment
# if you want different values, but keep them stable over time — changing
# either invalidates the Keychain ACL and triggers a fresh prompt.
IDENTITY="${ATLAS_CLI_SIGN_IDENTITY:-MongoDB Atlas CLI NG Dev}"
BUNDLE_ID="${ATLAS_CLI_SIGN_BUNDLE_ID:-com.mongodb.atlas-cli-ng.dev}"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <binary> [args...]" >&2
  exit 64
fi

BIN="$1"
shift

sign() {
  # Only meaningful on macOS with the codesign toolchain available.
  [[ "$(uname -s)" == "Darwin" ]] || return 0
  command -v codesign >/dev/null 2>&1 || return 0
  command -v security >/dev/null 2>&1 || return 0

  if ! security find-identity -v -p codesigning 2>/dev/null | grep -qF "$IDENTITY"; then
    # No dev identity installed: run unsigned so CI / first-time users are not
    # blocked. Only nudge on an interactive terminal to keep CI logs clean.
    if [[ -t 2 ]]; then
      echo "note: code-signing identity \"$IDENTITY\" not found — running unsigned." >&2
      echo "      run scripts/setup-codesign-identity.sh once to stop Keychain re-prompts." >&2
    fi
    return 0
  fi

  if ! codesign --force --sign "$IDENTITY" --identifier "$BUNDLE_ID" \
      --timestamp=none "$BIN" >/dev/null 2>&1; then
    echo "warning: codesign failed for $BIN — running unsigned (Keychain may re-prompt)." >&2
  fi
}

sign
exec "$BIN" "$@"
