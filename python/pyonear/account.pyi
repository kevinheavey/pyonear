from typing import ClassVar, Callable, Tuple, Optional, List, Sequence, Union
from pyonear.crypto_hash import CryptoHash

class FunctionCallPermission:
    def __hash__(self) -> int: ...
    allowance: Optional[int]
    method_names: List[str]
    receiver_id: str
    def __init__(
        self,
        receiver_id: str,
        method_names: Sequence[str],
        allowance: Optional[int] = None,
    ) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "FunctionCallPermission": ...
    @staticmethod
    def from_json(raw: str) -> "FunctionCallPermission": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class AccessKeyPermissionFieldless:
    FullAccess: ClassVar["AccessKeyPermissionFieldless"]
    def __hash__(self) -> int: ...
    def __eq__(self, other) -> bool: ...
    def __int__(self) -> int: ...

AccessKeyPermission = Union[FunctionCallPermission, AccessKeyPermissionFieldless]

class AccessKey:
    ACCESS_KEY_NONCE_RANGE_MULTIPLIER: ClassVar[int]
    def __hash__(self) -> int: ...
    nonce: int
    permission: AccessKeyPermission
    def __init__(self, nonce: int, permission: AccessKeyPermission) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "AccessKey": ...
    @staticmethod
    def from_json(raw: str) -> "AccessKey": ...
    @staticmethod
    def full_access() -> "AccessKey": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class AccountVersion:
    V1: ClassVar["AccountVersion"]
    def __hash__(self) -> int: ...
    def __eq__(self, other) -> bool: ...
    def __int__(self) -> int: ...

class Account:
    MAX_ACCOUNT_DELETION_STORAGE_USAGE: ClassVar[int]
    def __init__(
        self, amount: int, locked: int, code_hash: CryptoHash, storage_usage: int
    ) -> None: ...
    def amount(self) -> int: ...
    def code_hash(self) -> CryptoHash: ...
    @staticmethod
    def from_bytes(data: bytes) -> "Account": ...
    @staticmethod
    def from_json(raw: str) -> "Account": ...
    def locked(
        self,
    ) -> int: ...
    def set_amount(self, amount: int) -> None: ...
    def set_code_hash(self, code_hash: CryptoHash) -> None: ...
    def set_locked(self, locked: int) -> None: ...
    def set_storage_usage(self, storage_usage: int) -> None: ...
    def set_version(self, version: AccountVersion) -> None: ...
    def storage_usage(self) -> int: ...
    def to_json(self) -> str: ...
    def version(self) -> AccountVersion: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...