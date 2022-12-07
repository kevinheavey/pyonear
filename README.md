# Pyonear

WORK IN PROGRESS, PRE-RELEASE.

`pyonear` is a Python binding to the NEAR Rust API crates. It provides
wrapper types and functions for building, signing and (de)serializing transactions.
The wrapped types come from the [near-primitives](https://crates.io/crates/near-primitives),
[near-crypto](https://crates.io/crates/near-crypto) and
[near-vm-errors](https://crates.io/crates/near-vm-errors) crates.

## Development

Pre-requisites: Rust >= 1.65, Python >= 3.7, Poetry >= 1.1.14

### Steps

1. `poetry install` (one time only)
2. `poetry shell`
3. `maturin develop`
4. `pytest`
5. `make lint`
