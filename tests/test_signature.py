from pytest import raises
import hashlib
from pyonear.crypto import (
    ED25519PublicKey,
    Secp256K1PublicKey,
    ED25519SecretKey,
    Secp256K1SecretKey,
    Secp256K1Signature,
    ED25519Signature,
)
from pyonear.error.exception import ParseKeyError, ParseSignatureError


def test_str() -> None:
    ed_empty = ED25519PublicKey.empty()
    ed_as_str = str(ed_empty)
    assert ed_as_str == "ed25519:11111111111111111111111111111111"
    assert ED25519PublicKey.from_str(ed_as_str) == ed_empty
    secp_empty = Secp256K1PublicKey.empty()
    secp_as_str = str(secp_empty)
    assert (
        secp_as_str
        == "secp256k1:1111111111111111111111111111111111111111111111111111111111111111"
    )
    assert Secp256K1PublicKey.from_str(secp_as_str) == secp_empty
    with raises(ValueError):
        Secp256K1PublicKey.from_str(ed_as_str)
    with raises(ValueError):
        ED25519PublicKey.from_str(secp_as_str)


def test_sign_verify() -> None:
    for key_cls in (ED25519SecretKey, Secp256K1SecretKey):
        secret_key = key_cls.from_random()  # type: ignore
        public_key = secret_key.public_key()
        m = hashlib.sha256()
        m.update(b"123")
        data = m.digest()
        signature = secret_key.sign(data)
        assert signature.verify(data, public_key)


def test_json_serialize_ed25519() -> None:
    sk = ED25519SecretKey.from_seed("test")
    pk = sk.public_key()
    expected = '"ed25519:DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847"'
    assert pk.to_json() == expected
    assert pk == ED25519PublicKey.from_json(expected)
    assert pk == ED25519PublicKey.from_json(
        '"DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847"'
    )
    pk2 = ED25519PublicKey.from_str(str(pk))
    assert pk == pk2
    expected = '"ed25519:3KyUuch8pYP47krBq4DosFEVBMR5wDTMQ8AThzM8kAEcBQEpsPdYTZ2FPX5ZnSoLrerjwg66hwwJaW1wHzprd5k3"'
    assert sk.to_json() == expected
    assert sk == ED25519SecretKey.from_json(expected)

    signature = sk.sign(b"123")
    expected = '"ed25519:3s1dvZdQtcAjBksMHFrysqvF63wnyMHPA4owNQmCJZ2EBakZEKdtMsLqrHdKWQjJbSRN6kRknN2WdwSBLWGCokXj"'
    assert signature.to_json() == expected
    assert signature == ED25519Signature.from_json(expected)
    signature_str = str(signature)
    signature2 = ED25519Signature.from_str(signature_str)
    assert signature == signature2


def test_json_serialize_secp256k1() -> None:
    m = hashlib.sha256()
    m.update(b"123")
    data = m.digest()
    sk = Secp256K1SecretKey.from_seed("test")
    pk = sk.public_key()
    expected = '"secp256k1:5ftgm7wYK5gtVqq1kxMGy7gSudkrfYCbpsjL6sH1nwx2oj5NR2JktohjzB6fbEhhRERQpiwJcpwnQjxtoX3GS3cQ"'
    assert pk.to_json() == expected
    assert pk == Secp256K1PublicKey.from_json(expected)
    pk2 = Secp256K1PublicKey.from_str(str(pk))
    assert pk == pk2

    expected = '"secp256k1:X4ETFKtQkSGVoZEnkn7bZ3LyajJaK2b3eweXaKmynGx"'
    assert sk.to_json() == expected
    assert sk == Secp256K1SecretKey.from_json(expected)

    signature = sk.sign(data)
    expected = '"secp256k1:5N5CB9H1dmB9yraLGCo4ZCQTcF24zj4v2NT14MHdH3aVhRoRXrX3AhprHr2w6iXNBZDmjMS1Ntzjzq8Bv6iBvwth6"'
    assert signature.to_json() == expected
    assert signature == Secp256K1Signature.from_json(expected)
    signature_str = str(signature)
    signature2 = Secp256K1Signature.from_str(signature_str)
    assert signature == signature2


def test_borsh_serialization() -> None:
    m = hashlib.sha256()
    m.update(b"123")
    data = m.digest()
    pairs = (
        (ED25519SecretKey, ED25519PublicKey, ED25519Signature),
        (Secp256K1SecretKey, Secp256K1PublicKey, Secp256K1Signature),
    )
    for key_cls, pubkey_cls, sig_cls in pairs:
        sk = key_cls.from_seed("test")  # type: ignore
        pk = sk.public_key()
        bytes_ = bytes(pk)
        assert pubkey_cls.from_bytes(bytes_) == pk  # type: ignore

        signature = sk.sign(data)
        bytes_ = bytes(signature)
        assert sig_cls.from_bytes(bytes_) == signature  # type: ignore

        with raises(ParseKeyError):
            pubkey_cls.from_bytes(bytes([0]))  # type: ignore
        with raises(ParseSignatureError):
            sig_cls.from_bytes(bytes([0]))  # type: ignore


def test_invalid_data() -> None:
    invalid = '"secp256k1:2xVqteU8PWhadHTv99TGh3bSf"'
    with raises(ValueError):
        Secp256K1PublicKey.from_json(invalid)
    with raises(ValueError):
        Secp256K1SecretKey.from_json(invalid)
    with raises(ValueError):
        Secp256K1Signature.from_json(invalid)
