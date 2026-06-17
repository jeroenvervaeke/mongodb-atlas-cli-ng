#!/usr/bin/env bash
#
# Create a stable, self-signed code-signing identity used to sign local
# example/CLI builds, so macOS stops re-prompting for Keychain access on every
# rebuild.
#
# You normally don't need to run this by hand: the cargo runner
# (scripts/codesign-and-run.sh) calls it automatically the first time it needs
# the identity. Run it directly only if you want to provision the identity ahead
# of time. Either way the result is the same.
#
# Background and the runner that uses this identity live in
# scripts/codesign-and-run.sh and
# https://github.com/open-source-cooperative/keyring-rs/issues/272
#
# Safe to re-run: it does nothing if the identity already exists. The only
# expected prompt is a single request for your login password when the
# certificate is marked trusted for code signing. Set ATLAS_CLI_SIGN_QUIET=1 to
# suppress the closing tutorial (the runner sets this when it calls us).

set -euo pipefail

# Must match scripts/codesign-and-run.sh (both read the same env vars).
IDENTITY="${ATLAS_CLI_SIGN_IDENTITY:-MongoDB Atlas CLI NG Dev}"
KEYCHAIN="${ATLAS_CLI_SIGN_KEYCHAIN:-$HOME/Library/Keychains/login.keychain-db}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This setup is only needed on macOS; nothing to do on $(uname -s)."
  exit 0
fi

for tool in security codesign openssl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: required tool '$tool' not found on PATH." >&2
    exit 1
  fi
done

if security find-identity -v -p codesigning 2>/dev/null | grep -qF "$IDENTITY"; then
  echo "Code-signing identity \"$IDENTITY\" already exists — nothing to do."
  exit 0
fi

echo "Creating self-signed code-signing identity \"$IDENTITY\"…"

# We only get here when no *valid* identity exists (checked above). Remove any
# earlier untrusted or half-imported copies of this name so repeated runs can
# never accumulate duplicates in the keychain.
while security delete-identity -c "$IDENTITY" >/dev/null 2>&1; do :; done

workdir="$(mktemp -d)"
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT

# Self-signed leaf certificate marked for code signing. Written as a config
# file (rather than -addext) so it works with both OpenSSL and the LibreSSL
# that ships with macOS.
cat >"$workdir/req.cnf" <<EOF
[ req ]
distinguished_name = dn
x509_extensions    = ext
prompt             = no
[ dn ]
CN = $IDENTITY
[ ext ]
basicConstraints   = critical, CA:false
keyUsage           = critical, digitalSignature
extendedKeyUsage   = critical, codeSigning
EOF

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout "$workdir/key.pem" -out "$workdir/cert.pem" \
  -config "$workdir/req.cnf" >/dev/null 2>&1

# Import the private key and certificate as separate PEM files instead of
# bundling them into a PKCS#12. macOS forms an identity from any certificate
# whose private key is already in the keychain, and this avoids the whole class
# of "MAC verification failed during PKCS12 import" errors — both OpenSSL 3's
# newer PKCS#12 MAC/cipher defaults and the empty-password MAC encoding that
# Apple's importer rejects. -T grants codesign/security access to the key up
# front so signing doesn't pop its own Keychain prompt later.
security import "$workdir/key.pem"  -k "$KEYCHAIN" -T /usr/bin/codesign -T /usr/bin/security
security import "$workdir/cert.pem" -k "$KEYCHAIN"

# Trust the cert for code signing so `find-identity -v` and `codesign` accept
# it. This adjusts user trust settings and asks for your login password once —
# the only expected prompt.
echo "Marking the certificate trusted for code signing (you may be asked for"
echo "your login password once)…"
security add-trusted-cert -p codeSign -k "$KEYCHAIN" "$workdir/cert.pem" ||
  echo "warning: could not set trust automatically; see the note below." >&2

if security find-identity -v -p codesigning 2>/dev/null | grep -qF "$IDENTITY"; then
  if [[ -n "${ATLAS_CLI_SIGN_QUIET:-}" ]]; then
    echo "Code-signing identity \"$IDENTITY\" is ready."
  else
    cat <<EOF

Done — "$IDENTITY" is ready.

Building through cargo now signs automatically, e.g.:

    cargo run --example list_clusters --features derive

The first run still prompts once — click "Always Allow". Because every rebuild
now carries the same signature, macOS will not ask again.
EOF
  fi
else
  cat >&2 <<EOF

The certificate was created but is not yet a valid code-signing identity,
which usually means the trust step did not complete. Finish it in Keychain
Access:

  1. Open "Keychain Access" → "login" keychain → "My Certificates".
  2. Double-click the "$IDENTITY" certificate.
  3. Expand "Trust", set "Code Signing" to "Always Trust", then close
     (you'll be asked for your password).

Then re-run this script to verify.
EOF
  exit 1
fi
