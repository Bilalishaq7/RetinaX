# Getting Started with RetinaX

Welcome to RetinaX! This guide will help you set up your local environment and get started with development.

## Prerequisites

Before diving in, ensure you have the following installed on your system:
- **Rust 1.78.0+**: The core language for Soroban smart contracts. [Install Rust](https://www.rust-lang.org/tools/install).
- **Soroban CLI v23.1.4+**: Essential for compiling and deploying contracts on the Stellar network. [Install Soroban](https://soroban.stellar.org/docs/getting-started/installation).
- **Git**: For version control.
- **Make**: For using the provided Makefile automation.

## Environment Setup

### Automated Setup (Recommended)
The repository includes a setup script that automates the installation of targets, components, and network configurations:

```bash
# Clone the repository
git clone https://github.com/Ogbodo-Oluebube/RetinaX.git
cd RetinaX

# Run the setup script
chmod +x setup.sh
./setup.sh
```

### Manual Setup
If you prefer setting up manually:

```bash
# Install Rust targets
rustup target add wasm32-unknown-unknown
rustup component add rustfmt clippy rust-src

# Install Soroban CLI
cargo install --locked soroban-cli

# Configure Identity and Network
soroban config identity generate default
soroban config network add local \
    --rpc-url http://localhost:8000/soroban/rpc \
    --network-passphrase "Standalone Network ; February 2017"
```

## Building and Testing

Use the provided Makefile to easily compile and test your contracts:

```bash
# Build all contracts
make build

# Run unit and integration tests
make test
```

## Running the Local Network

To deploy contracts locally, you need a local Stellar network running:

```bash
make start-local
make deploy-local
```

Once running, you can interact with the contracts using the Soroban CLI or via the scripts located in the `scripts/` directory.

## Next Steps
- Explore the **[Interactive Protocol Playground](../website/index.html)**.
- Read through the **[Architecture Documentation](./architecture.md)** to understand the system design.
- Check out **[CONTRIBUTING.md](../CONTRIBUTING.md)** for our development standards and pull request process.
