# mongodb-atlas-cli

[![crates.io](https://img.shields.io/crates/v/mongodb-atlas-cli.svg)](https://crates.io/crates/mongodb-atlas-cli)
[![docs.rs](https://docs.rs/mongodb-atlas-cli/badge.svg)](https://docs.rs/mongodb-atlas-cli)

> Opinionated alternative CLI to interact with the MongoDB Atlas Admin API written in Rust

> [!WARNING]
> This project is a **work in progress** and is **not production ready**. APIs and functionality may change without notice.

## Overview

`mongodb-atlas-cli` is an alternative to the official [MongoDB Atlas CLI](https://www.mongodb.com/docs/atlas/cli/stable/) that provides both a command-line interface and a Rust library to interact with MongoDB Atlas.

### Goals

- **Drop-in replacement**: Configuration is fully compatible with the existing Atlas CLI, making migration seamless
- **Better UX**: Improved user experience with more intuitive commands and outputs
- **Library support**: Use as a Rust library to programmatically interact with MongoDB Atlas

## Installation

### From source

```bash
git clone https://github.com/jeroenvervaeke/mongodb-atlas-cli-ng
cd atlas-cli-ng
cargo install --path .
```

## Using as a Library

### Adding to your project

Add the following to your `Cargo.toml`:

```toml
[dependencies]
mongodb-atlas-cli = "0.0.1"
```

### Examples

Check out the [`examples/`](examples/) directory for usage examples. You can run them with:

```bash
cargo run --example print_default_profile
```

## Development

### Building

```bash
cargo build
```

### Running tests

```bash
cargo test
```

### Running examples

```bash
cargo run --example print_default_profile
```

#### macOS: stop the Keychain re-prompting on every rebuild

On macOS the Keychain ties each stored credential to the **code signature** of
the program that accesses it. Plain `cargo` builds are ad-hoc signed, and an
ad-hoc signature changes on every rebuild, so macOS treats each rebuild as a new
program and keeps asking for permission — even after you click *Always Allow*.
(See [keyring-rs#272](https://github.com/open-source-cooperative/keyring-rs/issues/272).)

The fix is to sign local builds with a stable identity, and it is wired to
happen automatically. The cargo runner in
[`.cargo/config.toml`](.cargo/config.toml) signs every binary before running it,
and **creates the signing identity on first use** if it doesn't exist yet — so
you just build as usual:

```bash
cargo run --example list_clusters --features derive
```

The first build creates a self-signed, code-signing-only dev certificate in your
login keychain (asking for your login password once), then signs and runs. Click
**Always Allow** on the Keychain prompt; because every rebuild now carries the
same signature, macOS won't ask again.

This is a local-dev certificate only — no Apple Developer account needed. It is a
no-op on other platforms and on CI (non-interactive builds simply run unsigned,
as before), so it never blocks a build. If you'd rather provision the identity
ahead of time, run `./scripts/setup-codesign-identity.sh` directly; set
`ATLAS_CLI_SIGN_AUTOSETUP=0` to opt out of the automatic setup.

## License

See [LICENSE](LICENSE) for details.

