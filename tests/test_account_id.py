from pytest import raises
from pyonear.account_id import AccountId

OK_ACCOUNT_IDS = (
    "aa",
    "a-a",
    "a-aa",
    "100",
    "0o",
    "com",
    "near",
    "bowen",
    "b-o_w_e-n",
    "b.owen",
    "bro.wen",
    "a.ha",
    "a.b-a.ra",
    "system",
    "over.9000",
    "google.com",
    "illia.cheapaccounts.near",
    "0o0ooo00oo00o",
    "alex-skidanov",
    "10-4.8-2",
    "b-o_w_e-n",
    "no_lols",
    "0123456789012345678901234567890123456789012345678901234567890123",
    # Valid, but can't be created
    "near.a",
)

BAD_ACCOUNT_IDS = (
    "a",
    "A",
    "Abc",
    "-near",
    "near-",
    "-near-",
    "near.",
    ".near",
    "near@",
    "@near",
    "неар",
    "@@@@@",
    "0__0",
    "0_-_0",
    "0_-_0",
    "..",
    "a..near",
    "nEar",
    "_bowen",
    "hello world",
    "abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz",
    "01234567890123456789012345678901234567890123456789012345678901234",
    # `@` separators are banned now
    "some-complex-address@gmail.com",
    "sub.buy_d1gitz@atata@b0-rg.c_0_m",
)


def test_is_valid_account_id() -> None:
    for account_id in OK_ACCOUNT_IDS:
        AccountId.validate(account_id)
    for account_id in BAD_ACCOUNT_IDS:
        with raises(ValueError):
            AccountId.validate(account_id)


def test_err_kind_classification() -> None:
    with raises(ValueError):
        AccountId("ErinMoriarty.near")
    with raises(ValueError):
        AccountId("-KarlUrban.near")
    with raises(ValueError):
        AccountId("anthonystarr.")
    with raises(ValueError):
        AccountId("jack__Quaid.near")


def test_is_valid_top_level_account_id() -> None:
    ok_top_level_account_ids = [
        "aa",
        "a-a",
        "a-aa",
        "100",
        "0o",
        "com",
        "near",
        "bowen",
        "b-o_w_e-n",
        "0o0ooo00oo00o",
        "alex-skidanov",
        "b-o_w_e-n",
        "no_lols",
        "0123456789012345678901234567890123456789012345678901234567890123",
    ]
    for account_id in ok_top_level_account_ids:
        assert AccountId(account_id).is_top_level()

    bad_top_level_account_ids = [
        "ƒelicia.near",  # fancy ƒ!
        "near.a",
        "b.owen",
        "bro.wen",
        "a.ha",
        "a.b-a.ra",
        "some-complex-address@gmail.com",
        "sub.buy_d1gitz@atata@b0-rg.c_0_m",
        "over.9000",
        "google.com",
        "illia.cheapaccounts.near",
        "10-4.8-2",
        "a",
        "A",
        "Abc",
        "-near",
        "near-",
        "-near-",
        "near.",
        ".near",
        "near@",
        "@near",
        "неар",
        "@@@@@",
        "0__0",
        "0_-_0",
        "0_-_0",
        "..",
        "a..near",
        "nEar",
        "_bowen",
        "hello world",
        "abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz",
        "01234567890123456789012345678901234567890123456789012345678901234",
        # Valid regex and length, but reserved
        "system",
    ]
    for account_id in bad_top_level_account_ids:
        try:
            assert not AccountId(account_id).is_top_level()
        except ValueError:
            pass


def test_is_valid_sub_account_id() -> None:
    ok_pairs = [
        ("test", "a.test"),
        ("test-me", "abc.test-me"),
        ("gmail.com", "abc.gmail.com"),
        ("gmail.com", "abc-lol.gmail.com"),
        ("gmail.com", "abc_lol.gmail.com"),
        ("gmail.com", "bro-abc_lol.gmail.com"),
        ("g0", "0g.g0"),
        ("1g", "1g.1g"),
        ("5-3", "4_2.5-3"),
    ]
    for (signer_id, sub_account_id) in ok_pairs:
        signer = AccountId(signer_id)
        sub_account = AccountId(sub_account_id)
        assert sub_account.is_sub_account_of(signer)

    bad_pairs = [
        ("test", ".test"),
        ("test", "test"),
        ("test", "a1.a.test"),
        ("test", "est"),
        ("test", ""),
        ("test", "st"),
        ("test5", "ббб"),
        ("test", "a-test"),
        ("test", "etest"),
        ("test", "a.etest"),
        ("test", "retest"),
        ("test-me", "abc-.test-me"),
        ("test-me", "Abc.test-me"),
        ("test-me", "-abc.test-me"),
        ("test-me", "a--c.test-me"),
        ("test-me", "a_-c.test-me"),
        ("test-me", "a-_c.test-me"),
        ("test-me", "_abc.test-me"),
        ("test-me", "abc_.test-me"),
        ("test-me", "..test-me"),
        ("test-me", "a..test-me"),
        ("gmail.com", "a.abc@gmail.com"),
        ("gmail.com", ".abc@gmail.com"),
        ("gmail.com", ".abc@gmail@com"),
        ("gmail.com", "abc@gmail@com"),
        ("test", "a@test"),
        ("test_me", "abc@test_me"),
        ("gmail.com", "abc@gmail.com"),
        ("gmail@com", "abc.gmail@com"),
        ("gmail.com", "abc-lol@gmail.com"),
        ("gmail@com", "abc_lol.gmail@com"),
        ("gmail@com", "bro-abc_lol.gmail@com"),
        (
            "gmail.com",
            "123456789012345678901234567890123456789012345678901234567890@gmail.com",
        ),
        (
            "123456789012345678901234567890123456789012345678901234567890",
            "1234567890.123456789012345678901234567890123456789012345678901234567890",
        ),
        ("aa", "ъ@aa"),
        ("aa", "ъ.aa"),
    ]
    for (signer_id, sub_account_id) in bad_pairs:
        try:
            signer = AccountId(signer_id)
            sub_account = AccountId(sub_account_id)
            assert not sub_account.is_sub_account_of(signer)
        except ValueError:
            pass


def test_is_account_id_64_len_hex() -> None:
    valid_64_len_hex_account_ids = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "6174617461746174617461746174617461746174617461746174617461746174",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "20782e20662e64666420482123494b6b6c677573646b6c66676a646b6c736667",
    ]
    for valid_account_id in valid_64_len_hex_account_ids:
        assert AccountId(valid_account_id).is_implicit()

    invalid_64_len_hex_account_ids = [
        "000000000000000000000000000000000000000000000000000000000000000",
        "6.74617461746174617461746174617461746174617461746174617461746174",
        "012-456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "fffff_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo",
        "00000000000000000000000000000000000000000000000000000000000000",
    ]
    for invalid_account_id in invalid_64_len_hex_account_ids:
        assert not AccountId(invalid_account_id).is_implicit()
