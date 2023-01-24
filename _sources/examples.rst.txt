========
Examples
========

.. note::
    `Pyonear` in its current form does intend to abstract away talking to a NEAR RPC server.
    Rather, it helps construct the data that you send to the RPC.

Create and serialize a transaction
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    >>> from pyonear.crypto import InMemorySigner, KeyType
    >>> from pyonear.account_id import AccountId
    >>> from pyonear.crypto_hash import CryptoHash
    >>> from pyonear.transaction import Transaction, TransferAction
    >>> signer_id = AccountId("alice.near")
    >>> signer = InMemorySigner.from_random(signer_id, KeyType.ED25519)
    >>> public_key = signer.public_key
    >>> nonce = 0
    >>> receiver_id = AccountId("bob.near")
    >>> block_hash = CryptoHash.default() # replace with a real blockhash
    >>> actions = [TransferAction(1_000_000)]
    >>> transaction = Transaction(signer_id, public_key, nonce, receiver_id, block_hash, actions).sign(signer)
    >>> bytes(transaction)
    b'\n\x00\x00\x00alice.near\x00\xeajP0\x86\xfb\x9cd\x8f\xd3\xcc_\x87\xd5\xc2_\xd4\xce\xb4,tR\xc1\xa65\x17\x91\xb9\xac\x07\x8e\x93\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00bob.near\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03@B\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\x8fo\x0f\x18\xf9\x91\x82\\{\xd1PU\xa7\xe5<b*gq\x8d=\xc6o\x8c\xc7\x1dU\x8fE\xd4\xbe\x88\xba\x82\x9eql\x87\xc4n(\xf19\x14u\xa3\xcd\x9e\xcc\xd3Tv2U\xae(o\xf2\x03\xae\xca\xef\x0f'
    >>> transaction.to_base64()
    'CgAAAGFsaWNlLm5lYXIA++M56uPzUi8ezkHqJBLjc7ZCzJk88zoIpF5XkjUM13kAAAAAAAAAAAgAAABib2IubmVhcgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAANAQg8AAAAAAAAAAAAAAAAAALK42W7t/vpUmDAgtChTUWEVvSE3cQZWRla8spN6KfNv9fWn16klROeblzH480b0a+NSL16YfnvWLnd2C9KLTQk='

This base64 string can be passed to the `broadcast_tx_* <https://docs.near.org/api/rpc/transactions#send-transaction-async>`_ methods
of the RPC API.

Serialize and deserialize an account
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    >>> from pyonear.crypto_hash import crypto_hash, CryptoHash
    >>> from pyonear.account import Account
    >>> acc = Account(1_000_000, 1_000_000, CryptoHash.default(), 100)
    >>> bytes_ = bytes(acc)
    >>> crypto_hash(bytes_)
    CryptoHash(
        `EVk5UaxBe8LQ8r8iD5EAxVBs6TJcMDKqyH7PBuho6bBJ`,
    )
    >>> assert Account.from_bytes(bytes_) == acc

Save keys to a file
^^^^^^^^^^^^^^^^^^^

::

    >>> from pyonear.crypto import ED25519SecretKey, KeyFile
    >>> from pyonear.account_id import AccountId
    >>> account_id = AccountId("example")
    >>> secret_key = ED25519SecretKey.from_str("ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr")
    >>> keyfile = KeyFile(account_id, secret_key.public_key(), secret_key)
    >>> keyfile.write_to_file("tmp.json")

Verify a signature
^^^^^^^^^^^^^^^^^^

::

    >>> import hashlib
    >>> from pyonear.crypto import ED25519SecretKey
    >>> secret_key = ED25519SecretKey.from_random()
    >>> public_key = secret_key.public_key()
    >>> m = hashlib.sha256()
    >>> m.update(b"123")
    >>> data = m.digest()
    >>> signature = secret_key.sign(data)
    >>> assert signature.verify(data, public_key)
    >>> signature.verify(data, public_key)
    True


Multiple actions in one transaction
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    >>> from pyonear.crypto import ED25519PublicKey
    >>> from pyonear.account_id import AccountId
    >>> from pyonear.crypto_hash import CryptoHash
    >>> from pyonear.transaction import Transaction, CreateAccountAction, DeployContractAction, FunctionCallAction, TransferAction, StakeAction, AddKeyAction, DeleteKeyAction, DeleteAccountAction
    >>> from pyonear.account import AccessKey, FunctionCallPermission
    >>> public_key = ED25519PublicKey.from_str(
    ...     "22skMptHjFWNyuEWY22ftn2AbLPSYpmYwGJRGwpNHbTV"
    ... )
    >>> transaction = Transaction(
    ...     signer_id=AccountId("test.near"),
    ...     public_key=public_key,
    ...     nonce=1,
    ...     receiver_id=AccountId("123"),
    ...     block_hash=CryptoHash.default(),
    ...     actions=[
    ...         CreateAccountAction(),
    ...         DeployContractAction([1, 2, 3]),
    ...         FunctionCallAction(
    ...             method_name="qqq",
    ...             args=[1, 2, 3],
    ...             gas=1_000,
    ...             deposit=1_000_000,
    ...         ),
    ...         TransferAction(deposit=123),
    ...         StakeAction(public_key=public_key, stake=1_000_000),
    ...         AddKeyAction(
    ...             public_key=public_key,
    ...             access_key=AccessKey(
    ...                 nonce=0,
    ...                 permission=FunctionCallPermission(
    ...                     allowance=None,
    ...                     receiver_id="zzz",
    ...                     method_names=["www"],
    ...                 ),
    ...             ),
    ...         ),
    ...         DeleteKeyAction(public_key),
    ...         DeleteAccountAction(AccountId("123")),
    ...     ],
    ... )
    >>>


