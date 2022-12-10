from pyonear.crypto_hash import crypto_hash, CryptoHash
from pyonear.account import AccountVersion, Account


def test_account_serialization() -> None:
    acc = Account(1_000_000, 1_000_000, CryptoHash.default(), 100)
    bytes_ = bytes(acc)
    assert str(crypto_hash(bytes_)) == "EVk5UaxBe8LQ8r8iD5EAxVBs6TJcMDKqyH7PBuho6bBJ"


def test_account_deserialization() -> None:
    new_account = Account(100, 200, CryptoHash.default(), 300)
    assert new_account.version == AccountVersion.V1
    new_bytes = bytes(new_account)
    deserialized_account = Account.from_bytes(new_bytes)
    assert deserialized_account == new_account
