# RISC Zero Benchmark circuit

# Overview
This is a repo containing the Risc Zero code used to benchmark proving time for your prover hardware. The circuit contains a single ED25519 signature verification, which is exactly 1_256_081 cycles. The proof generation time in seconds is later used by the ProofPlus protocol to set each individual task's deadline and to calculate the task rewards.

## Dependencies

First, [install Rust] and then restart your terminal.

```sh
# Install Rust
curl https://sh.rustup.rs -sSf | sh
```

Next, you will need to install the `cargo risczero` tool.
We'll use [`cargo binstall`][cargo-binstall] to get `cargo-risczero` installed, and then install the `risc0` toolchain.
See [RISC Zero installation] for more details.

```sh
cargo install cargo-binstall
cargo binstall cargo-risczero
cargo risczero install
```

Now you have all the tools you need to develop and deploy an application with [RISC Zero].

## Quick Start

First, install the RISC Zero toolchain using the [instructions above](#dependencies).

Update submodules with:

```sh
git submodule update --init --recursive
```

### Build the Code

- Builds for zkVM benchmark program

  ```sh
  cargo build
  ```

### Run local benchmark

 ```sh
  time cargo test
  ```

[RISC Zero installation]: https://dev.risczero.com/api/zkvm/install
[RISC Zero zkVM]: https://dev.risczero.com/zkvm
[RISC Zero]: https://www.risczero.com/
[cargo-binstall]: https://github.com/cargo-bins/cargo-binstall#cargo-binaryinstall
[install Rust]: https://doc.rust-lang.org/cargo/getting-started/installation.html
