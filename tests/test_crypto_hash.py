from pytest import raises
from pyonear.crypto_hash import CryptoHash, crypto_hash


def test_base58_successes() -> None:
    pairs = (
        ("11111111111111111111111111111111", CryptoHash.zero()),
        ("CjNSmWXTWhC3EhRVtqLhRmWMTkRbU96wUACqxMtV1uGf", crypto_hash(bytes([0, 1, 2]))),
    )
    for (encoded, hash_) in pairs:
        assert encoded == str(hash_)
        assert hash_ == CryptoHash.from_str(encoded)
        json = '"{}"'.format(encoded)
        assert json == hash_.to_json()
        assert hash_ == CryptoHash.from_json(json)


def test_from_str_failures() -> None:
    def expect_err(input_: str, want_err: str) -> None:
        with raises(ValueError) as excinfo:
            CryptoHash.from_str(input_)
        assert excinfo.value.args[0].startswith(want_err)

    # Invalid characters
    expect_err(
        "foo-bar-baz", "provided string contained invalid character '-' at byte 3"
    )

    # Wrong length
    encoded_vals = (
        "CjNSmWXTWhC3ELhRmWMTkRbU96wUACqxMtV1uGf",
        "",
        "1" * 31,
        "1" * 33,
        "1" * 1000,
    )
    for encoded in encoded_vals:
        expect_err(encoded, "incorrect length for hash")


def test_serde_deserialise_failures() -> None:
    def expect_err(input_: str, want_err: str) -> None:
        with raises(ValueError) as excinfo:
            CryptoHash.from_json(input_)
        assert excinfo.value.args[0].startswith(want_err)

    expect_err('"foo-bar-baz"', "provided string contained invalid character")
    # Wrong length
    encoded_vals = (
        '"CjNSmWXTWhC3ELhRmWMTkRbU96wUACqxMtV1uGf"',
        '""',
        '"{}"'.format("1" * 31),
        '"{}"'.format("1" * 33),
        '"{}"'.format("1" * 1000),
    )
    for encoded in encoded_vals:
        expect_err(encoded, "invalid length")
