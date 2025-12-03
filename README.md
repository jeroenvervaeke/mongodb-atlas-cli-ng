# atlas-cli

> Opinionated alternative CLI to interact with the MongoDB Atlas Admin API written in Rust

> [!WARNING]
> This project is a **work in progress** and is **not production ready**. APIs and functionality may change without notice.

## Overview

`atlas-cli` is an alternative to the official [MongoDB Atlas CLI](https://www.mongodb.com/docs/atlas/cli/stable/) that provides both a command-line interface and a Rust library to interact with MongoDB Atlas.

### Goals

- **Drop-in replacement**: Configuration is fully compatible with the existing Atlas CLI, making migration seamless
- **Better UX**: Improved user experience with more intuitive commands and outputs
- **Library support**: Use as a Rust library to programmatically interact with MongoDB Atlas

## Installation

### From source

```bash
git clone https://github.com/jeroenvervaeke/atlas-cli-ng
cd atlas-cli-ng
cargo install --path .
```

## Using as a Library

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

## License

See [LICENSE](LICENSE) for details.

