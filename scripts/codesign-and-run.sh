#!/usr/bin/env bash
#
# Cargo target runner for macOS: codesign a freshly built binary with a stable,
# self-signed identity, then exec it. If that identity does not exist yet it is
# created on first use, so signing "just works" with no separate setup step.
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
# --example ...` (and `cargo run`, `cargo test`) sign automatically. A runner is
# the right seam here because Cargo has no post-build hook and a build.rs runs
# *before* the binary is compiled — see .cargo/config.toml for that rationale.
#
# On the first build where the signing identity is missing, this calls
# scripts/setup-codesign-identity.sh to create it (one login-password prompt).
# That only happens on an interactive terminal, so CI and other non-interactive
# builds stay a safe no-op and run unsigned — nothing ever blocks a build. Set
# ATLAS_CLI_SIGN_AUTOSETUP=0 to skip auto-setup and sign only when an identity
# already exists.

set -euo pipefail

# Shared with scripts/setup-codesign-identity.sh. Override via the environment
# if you want different values, but keep them stable over time — changing
# either invalidates the Keychain ACL and triggers a fresh prompt.
IDENTITY="${ATLAS_CLI_SIGN_IDENTITY:-MongoDB Atlas CLI NG Dev}"
BUNDLE_ID="${ATLAS_CLI_SIGN_BUNDLE_ID:-com.mongodb.atlas-cli-ng.dev}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <binary> [args...]" >&2
  exit 64
fi

BIN="$1"
shift

identity_present() {
  security find-identity -v -p codesigning 2>/dev/null | grep -qF "$IDENTITY"
}

sign() {
  # Only meaningful on macOS with the codesign toolchain available.
  [[ "$(uname -s)" == "Darwin" ]] || return 0
  command -v codesign >/dev/null 2>&1 || return 0
  command -v security >/dev/null 2>&1 || return 0

  if ! identity_present; then
    # Create the identity on demand, but only when a human is present to answer
    # the one-time trust/password prompt. On CI or any non-interactive build we
    # leave it alone and run unsigned, so nothing blocks.
    if [[ -t 2 && "${ATLAS_CLI_SIGN_AUTOSETUP:-1}" != "0" \
          && -x "$SCRIPT_DIR/setup-codesign-identity.sh" ]]; then
      echo "note: code-signing identity \"$IDENTITY\" not found — setting it up once…" >&2
      # Route setup output to stderr so it never lands on the program's stdout,
      # and don't let a declined/failed setup abort the build (we just run
      # unsigned in that case).
      ATLAS_CLI_SIGN_QUIET=1 "$SCRIPT_DIR/setup-codesign-identity.sh" >&2 || true
    fi

    if ! identity_present; then
      [[ -t 2 ]] && echo "note: running \"$BIN\" unsigned; Keychain may re-prompt." >&2
      return 0
    fi
  fi

  if ! codesign --force --sign "$IDENTITY" --identifier "$BUNDLE_ID" \
      --timestamp=none "$BIN" >/dev/null 2>&1; then
    echo "warning: codesign failed for $BIN — running unsigned (Keychain may re-prompt)." >&2
  fi
}

sign
exec "$BIN" "$@"
