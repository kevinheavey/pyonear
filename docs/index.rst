.. image:: logo.png
    :scale: 70 %

pyonear
=======

``pyonear`` provides Python bindings for NEAR Rust primitives.
It provides wrapper types and functions for building, signing and (de)serializing transactions.
The wrapped types come from the `near-primitives <https://crates.io/crates/near-primitives>`_,
`near-crypto <https://crates.io/crates/near-crypto>`_ and
`near-vm-errors <https://crates.io/crates/near-vm-errors>`_ crates.

Installation
^^^^^^^^^^^^

::

    pip install pyonear

.. note:: Requires Python >= 3.7.

Example Usage
^^^^^^^^^^^^^

::

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



.. toctree::
   :maxdepth: 3
   :caption: Contents:

   self
   examples
   api_reference/index
