from pyonear.crypto import InMemorySigner, KeyType, ED25519PublicKey, ED25519Signature
from pyonear.crypto_hash import CryptoHash, crypto_hash
from pyonear.transaction import (
    Transaction,
    verify_transaction_signature,
    CreateAccountAction,
    FunctionCallAction,
    DeployContractAction,
    DeleteAccountAction,
    DeleteKeyAction,
    SignedTransaction,
    ExecutionOutcome,
    ExecutionOutcomeWithId,
    TransferAction,
    StakeAction,
    AddKeyAction,
    ExecutionMetadataFieldless,
)
from pyonear.account_id import AccountId
from pyonear.account import FunctionCallPermission, AccessKey


def test_verify_transaction() -> None:
    signer = InMemorySigner.from_random(AccountId("test"), KeyType.ED25519)
    transaction = Transaction(
        signer_id=AccountId("test"),
        public_key=signer.public_key,
        nonce=0,
        receiver_id=AccountId("test"),
        block_hash=CryptoHash.default(),
        actions=[],
    ).sign(signer)
    wrong_public_key = ED25519PublicKey.from_seed("wrong")
    valid_keys = [signer.public_key, wrong_public_key]
    assert verify_transaction_signature(transaction, valid_keys)

    invalid_keys = [wrong_public_key]
    assert not verify_transaction_signature(transaction, invalid_keys)

    bytes_ = bytes(transaction)
    decoded_tx = SignedTransaction.from_bytes(bytes_)
    assert verify_transaction_signature(decoded_tx, valid_keys)


def test_serialize_transaction() -> None:
    public_key = ED25519PublicKey.from_str(
        "22skMptHjFWNyuEWY22ftn2AbLPSYpmYwGJRGwpNHbTV"
    )
    transaction = Transaction(
        signer_id=AccountId("test.near"),
        public_key=public_key,
        nonce=1,
        receiver_id=AccountId("123"),
        block_hash=CryptoHash.default(),
        actions=[
            CreateAccountAction(),
            DeployContractAction([1, 2, 3]),
            FunctionCallAction(
                method_name="qqq",
                args=[1, 2, 3],
                gas=1_000,
                deposit=1_000_000,
            ),
            TransferAction(deposit=123),
            StakeAction(public_key=public_key, stake=1_000_000),
            AddKeyAction(
                public_key=public_key,
                access_key=AccessKey(
                    nonce=0,
                    permission=FunctionCallPermission(
                        allowance=None,
                        receiver_id="zzz",
                        method_names=["www"],
                    ),
                ),
            ),
            DeleteKeyAction(public_key),
            DeleteAccountAction(AccountId("123")),
        ],
    )
    signed_tx = SignedTransaction(ED25519Signature.empty(), transaction)
    new_signed_tx = SignedTransaction.from_bytes(bytes(signed_tx))

    assert str(new_signed_tx.hash) == "4GXvjMFN6wSxnU9jEVT8HbXP5Yk6yELX9faRSKp6n9fX"


def test_outcome_to_hashes() -> None:
    outcome = ExecutionOutcome(
        status=[123],
        logs=["123", "321"],
        receipt_ids=[],
        gas_burnt=123,
        tokens_burnt=1234000,
        executor_id=AccountId("alice"),
        metadata=ExecutionMetadataFieldless.V1,
    )
    id = CryptoHash([42] * 32)
    outcome_with_id = ExecutionOutcomeWithId(id, outcome)
    assert [
        id,
        CryptoHash.from_str("5JQs5ekQqKudMmYejuccbtEu1bzhQPXa92Zm4HdV64dQ"),
        crypto_hash(b"123"),
        crypto_hash(b"321"),
    ] == outcome_with_id.to_hashes()
