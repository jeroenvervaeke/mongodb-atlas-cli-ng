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

To fix it, sign local builds with a stable identity. Run this **once**:

```bash
./scripts/setup-codesign-identity.sh
```

It creates a self-signed, code-signing-only dev certificate in your login
keychain (asking for your login password a single time). After that, the cargo
runner configured in [`.cargo/config.toml`](.cargo/config.toml) automatically
signs every binary with the same identity and bundle id before running it:

```bash
cargo run --example list_clusters --features derive
```

The first run still prompts once — click **Always Allow**. Because every rebuild
now carries the same signature, macOS won't ask again. This is a local-dev
certificate only; it requires no Apple Developer account and is a no-op on other
platforms and in CI (builds simply run unsigned, as before).

## License

See [LICENSE](LICENSE) for details.

