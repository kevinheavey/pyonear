from typing import ClassVar, Union, List, Tuple, Callable, Sequence

from pyonear.account_id import AccountId

class AltBn128InvalidInput:
    msg: str
    def __init__(self, msg: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "AltBn128InvalidInput": ...
    @staticmethod
    def from_json(raw: str) -> "AltBn128InvalidInput": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class CacheErrorFieldless:
    DeserializationError: ClassVar["CacheErrorFieldless"]
    ReadError: ClassVar["CacheErrorFieldless"]
    WriteError: ClassVar["CacheErrorFieldless"]
    def __init__(self) -> None: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __int__(self) -> int: ...

class CodeDoesNotExist:
    account_id: AccountId
    def __init__(self, account_id: AccountId) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "CodeDoesNotExist": ...
    @staticmethod
    def from_json(raw: str) -> "CodeDoesNotExist": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class ContractSizeExceeded:
    limit: int
    size: int
    def __init__(self, size: int, limit: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "ContractSizeExceeded": ...
    @staticmethod
    def from_json(raw: str) -> "ContractSizeExceeded": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class Deprecated:
    method_name: str
    def __init__(self, method_name: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "Deprecated": ...
    @staticmethod
    def from_json(raw: str) -> "Deprecated": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class ECRecoverError:
    msg: str
    def __init__(self, msg: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "ECRecoverError": ...
    @staticmethod
    def from_json(raw: str) -> "ECRecoverError": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class Ed25519VerifyInvalidInput:
    msg: str
    def __init__(self, msg: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "Ed25519VerifyInvalidInput": ...
    @staticmethod
    def from_json(raw: str) -> "Ed25519VerifyInvalidInput": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class FunctionCallErrorSerFieldless:
    WasmUnknownError: ClassVar["FunctionCallErrorSerFieldless"]
    _EVMError: ClassVar["FunctionCallErrorSerFieldless"]
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __int__(self) -> int: ...

class GuestPanic:
    panic_msg: str
    def __init__(self, panic_msg: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "GuestPanic": ...
    @staticmethod
    def from_json(raw: str) -> "GuestPanic": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class HostErrorFieldless:
    BadUTF16: ClassVar["HostErrorFieldless"]
    BadUTF8: ClassVar["HostErrorFieldless"]
    BalanceExceeded: ClassVar["HostErrorFieldless"]
    CannotAppendActionToJointPromise: ClassVar["HostErrorFieldless"]
    CannotReturnJointPromise: ClassVar["HostErrorFieldless"]
    EmptyMethodName: ClassVar["HostErrorFieldless"]
    GasExceeded: ClassVar["HostErrorFieldless"]
    GasLimitExceeded: ClassVar["HostErrorFieldless"]
    IntegerOverflow: ClassVar["HostErrorFieldless"]
    InvalidAccountId: ClassVar["HostErrorFieldless"]
    InvalidMethodName: ClassVar["HostErrorFieldless"]
    InvalidPublicKey: ClassVar["HostErrorFieldless"]
    MemoryAccessViolation: ClassVar["HostErrorFieldless"]
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __int__(self) -> int: ...

class InvalidIteratorIndex:
    iterator_index: int
    def __init__(self, iterator_index: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "InvalidIteratorIndex": ...
    @staticmethod
    def from_json(raw: str) -> "InvalidIteratorIndex": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class InvalidPromiseIndex:
    promise_idx: int
    def __init__(self, promise_idx: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "InvalidPromiseIndex": ...
    @staticmethod
    def from_json(raw: str) -> "InvalidPromiseIndex": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class InvalidPromiseResultIndex:
    result_idx: int
    def __init__(self) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "InvalidPromiseResultIndex": ...
    @staticmethod
    def from_json(raw: str) -> "InvalidPromiseResultIndex": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class InvalidReceiptIndex:
    receipt_index: int
    def __init__(self, receipt_index: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "InvalidReceiptIndex": ...
    @staticmethod
    def from_json(raw: str) -> "InvalidReceiptIndex": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class InvalidRegisterId:
    register_id: int
    def __init__(self, register_id: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "InvalidRegisterId": ...
    @staticmethod
    def from_json(raw: str) -> "InvalidRegisterId": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class IteratorWasInvalidated:
    iterator_index: int
    def __init__(self, iterator_index: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "IteratorWasInvalidated": ...
    @staticmethod
    def from_json(raw: str) -> "IteratorWasInvalidated": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class KeyLengthExceeded:
    length: int
    limit: int
    def __init__(self, length: int, limit: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "KeyLengthExceeded": ...
    @staticmethod
    def from_json(raw: str) -> "KeyLengthExceeded": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class LinkError:
    msg: str
    def __init__(self, msg: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "LinkError": ...
    @staticmethod
    def from_json(raw: str) -> "LinkError": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class MethodResolveError:
    MethodEmptyName: ClassVar["MethodResolveError"]
    MethodInvalidSignature: ClassVar["MethodResolveError"]
    MethodNotFound: ClassVar["MethodResolveError"]
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __int__(self) -> int: ...

class NumberInputDataDependenciesExceeded:
    limit: int
    number_of_input_data_dependencies: int
    def __init__(self, number_of_input_data_dependencies: int, limit: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "NumberInputDataDependenciesExceeded": ...
    @staticmethod
    def from_json(raw: str) -> "NumberInputDataDependenciesExceeded": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class NumberOfLogsExceeded:
    limit: int
    def __init__(self, limit: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "NumberOfLogsExceeded": ...
    @staticmethod
    def from_json(raw: str) -> "NumberOfLogsExceeded": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class NumberPromisesExceeded:
    limit: int
    number_of_promises: int
    def __init__(self, number_of_promises: int, limit: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "NumberPromisesExceeded": ...
    @staticmethod
    def from_json(raw: str) -> "NumberPromisesExceeded": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class PrepareError:
    Deserialization: ClassVar["PrepareError"]
    GasInstrumentation: ClassVar["PrepareError"]
    Instantiate: ClassVar["PrepareError"]
    InternalMemoryDeclared: ClassVar["PrepareError"]
    Memory: ClassVar["PrepareError"]
    Serialization: ClassVar["PrepareError"]
    StackHeightInstrumentation: ClassVar["PrepareError"]
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __int__(self) -> int: ...

class ProhibitedInView:
    method_name: str
    def __init__(self, method_name: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "ProhibitedInView": ...
    @staticmethod
    def from_json(raw: str) -> "ProhibitedInView": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class ReturnedValueLengthExceeded:
    length: int
    limit: int
    def __init__(self, length: int, limit: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "ReturnedValueLengthExceeded": ...
    @staticmethod
    def from_json(raw: str) -> "ReturnedValueLengthExceeded": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class SerializationError:
    hash: List[int]
    def __init__(self, hash: Union[Sequence[int], bytes]) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "SerializationError": ...
    @staticmethod
    def from_json(raw: str) -> "SerializationError": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class TotalLogLengthExceeded:
    length: int
    limit: int
    def __init__(self, length: int, limit: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "TotalLogLengthExceeded": ...
    @staticmethod
    def from_json(raw: str) -> "TotalLogLengthExceeded": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class UnsupportedCompiler:
    msg: str
    def __init__(self, msg: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "UnsupportedCompiler": ...
    @staticmethod
    def from_json(raw: str) -> "UnsupportedCompiler": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class ValueLengthExceeded:
    length: int
    limit: int
    def __init__(self, length: int, limit: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "ValueLengthExceeded": ...
    @staticmethod
    def from_json(raw: str) -> "ValueLengthExceeded": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class WasmTrap:
    CallIndirectOOB: ClassVar["WasmTrap"]
    GenericTrap: ClassVar["WasmTrap"]
    IllegalArithmetic: ClassVar["WasmTrap"]
    IncorrectCallIndirectSignature: ClassVar["WasmTrap"]
    IndirectCallToNull: ClassVar["WasmTrap"]
    MemoryOutOfBounds: ClassVar["WasmTrap"]
    MisalignedAtomicAccess: ClassVar["WasmTrap"]
    StackOverflow: ClassVar["WasmTrap"]
    Unreachable: ClassVar["WasmTrap"]
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __int__(self) -> int: ...

class WasmerCompileError:
    msg: str
    def __init__(self, msg: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "WasmerCompileError": ...
    @staticmethod
    def from_json(raw: str) -> "WasmerCompileError": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

HostError = Union[
    HostErrorFieldless,
    GuestPanic,
    InvalidPromiseIndex,
    InvalidPromiseResultIndex,
    InvalidRegisterId,
    IteratorWasInvalidated,
    InvalidReceiptIndex,
    InvalidIteratorIndex,
    ProhibitedInView,
    NumberOfLogsExceeded,
    KeyLengthExceeded,
    ValueLengthExceeded,
    TotalLogLengthExceeded,
    NumberPromisesExceeded,
    NumberInputDataDependenciesExceeded,
    ReturnedValueLengthExceeded,
    ContractSizeExceeded,
    Deprecated,
    ECRecoverError,
    Ed25519VerifyInvalidInput,
    AltBn128InvalidInput,
]

CompilationError = Union[
    CodeDoesNotExist, PrepareError, WasmerCompileError, UnsupportedCompiler
]

FunctionCallErrorSer = Union[
    FunctionCallErrorSerFieldless,
    CompilationError,
    LinkError,
    MethodResolveError,
    WasmTrap,
    HostError,
    str,
]

CacheError = Union[CacheErrorFieldless, SerializationError]
