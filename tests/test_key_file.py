import sys
from pathlib import Path
from pytest import raises
from pyonear.crypto import ED25519SecretKey, KeyFile
from pyonear.account_id import AccountId

ACCOUNT_ID = "example"
SECRET_KEY = "ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr"
KEY_FILE_CONTENTS = """{
  "account_id": "example",
  "public_key": "ed25519:6DSjZ8mvsRZDvFqFxo8tCKePG96omXW7eVYVSySmDk8e",
  "secret_key": "ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr"
}"""


def test_to_file(tmp_path: Path) -> None:
    path = tmp_path / "key-file"

    account_id = AccountId(ACCOUNT_ID)
    secret_key = ED25519SecretKey.from_str(SECRET_KEY)
    public_key = secret_key.public_key()
    key = KeyFile(account_id, public_key, secret_key)
    key.write_to_file(path)

    assert KEY_FILE_CONTENTS == path.read_text()

    if sys.platform == "linux":
        got = path.stat().st_mode
        assert (got & 0o777) == 0o600


def load(contents: bytes, tempdir: Path) -> None:
    path = tempdir / "key-file"
    path.write_bytes(contents)
    key = KeyFile.from_file(path)

    assert ACCOUNT_ID == str(key.account_id)
    secret_key = ED25519SecretKey.from_str(SECRET_KEY)
    assert secret_key == key.secret_key
    assert secret_key.public_key() == key.public_key


def test_from_file(tmp_path: Path) -> None:
    load(KEY_FILE_CONTENTS.encode(), tmp_path)

    # Test private_key alias for secret_key works.
    contents = KEY_FILE_CONTENTS.replace("secret_key", "private_key")
    load(contents.encode(), tmp_path)

    # Test private_key is mutually exclusive with secret_key.
    with raises(OSError) as excinfo:
        load(
            b"""{
            "account_id": "example",
            "public_key": "ed25519:6DSjZ8mvsRZDvFqFxo8tCKePG96omXW7eVYVSySmDk8e",
            "secret_key": "ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr",
            "private_key": "ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr"
        }""",
            tmp_path,
        )
    err_msg = excinfo.value.args[0]
    assert err_msg.startswith("duplicate field")
