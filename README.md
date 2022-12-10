# Pyonear

`pyonear` is a Python binding to the NEAR Rust API crates. It provides
wrapper types and functions for building, signing and (de)serializing transactions.
The wrapped types come from the [near-primitives](https://crates.io/crates/near-primitives),
[near-crypto](https://crates.io/crates/near-crypto) and
[near-vm-errors](https://crates.io/crates/near-vm-errors) crates.

## Example usage

```python
>>> from pyonear.crypto import InMemorySigner, KeyType
>>> from pyonear.account_id import AccountId
>>> from pyonear.crypto_hash import CryptoHash
>>> from pyonear.transaction import Transaction, TransferAction
>>> signer = InMemorySigner.from_random(AccountId("alice.near"), KeyType.ED25519)
>>> signer_id = AccountId("alice.near")
>>> signer = InMemorySigner.from_random(signer_id, KeyType.ED25519)
>>> public_key = signer.public_key
>>> nonce = 0
>>> receiver_id = AccountId("bob.near")
>>> block_hash = CryptoHash.default() # replace with a real blockhash
>>> actions = [TransferAction(1_000_000)]
>>> transaction = Transaction(signer_id, public_key, nonce, receiver_id, block_hash, actions).sign(signer)
>>> transaction.to_base64()
'CgAAAGFsaWNlLm5lYXIA++M56uPzUi8ezkHqJBLjc7ZCzJk88zoIpF5XkjUM13kAAAAAAAAAAAgAAABib2IubmVhcgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAANAQg8AAAAAAAAAAAAAAAAAALK42W7t/vpUmDAgtChTUWEVvSE3cQZWRla8spN6KfNv9fWn16klROeblzH480b0a+NSL16YfnvWLnd2C9KLTQk='
```

## Development

Pre-requisites: Rust >= 1.65, Python >= 3.7, Poetry >= 1.1.14

### Steps

1. `poetry install` (one time only)
2. `poetry shell`
3. `maturin develop`
4. `pytest`
5. `make lint`
