from typing import ClassVar, Tuple, Callable, Union, Optional

from pyonear.crypto import PublicKey
from pyonear.account_id import AccountId
from pyonear.error.vm import FunctionCallErrorSer

class AccessKeyNotFound:
    account_id: AccountId
    public_key: PublicKey
    def __init__(self) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "AccessKeyNotFound": ...
    @staticmethod
    def from_json(raw: str) -> "AccessKeyNotFound": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class AccountAlreadyExists:
    account_id: AccountId
    def __init__(self, account_id: AccountId) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "AccountAlreadyExists": ...
    @staticmethod
    def from_json(raw: str) -> "AccountAlreadyExists": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class AccountDoesNotExist:
    account_id: AccountId
    def __init__(self, account_id: AccountId) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "AccountDoesNotExist": ...
    @staticmethod
    def from_json(raw: str) -> "AccountDoesNotExist": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

ActionErrorKind = Union[
    AccountAlreadyExists,
    AccountDoesNotExist,
    CreateAccountOnlyByRegistrar,
    CreateAccountNotAllowed,
    ActorNoPermission,
    DeleteKeyDoesNotExist,
    AddKeyAlreadyExists,
    DeleteAccountStaking,
    LackBalanceForState,
    TriesToUnstake,
    TriesToStake,
    InsufficientStake,
    FunctionCallErrorSer,
    ReceiptValidationError,
    OnlyImplicitAccountCreationAllowed,
    DeleteAccountWithLargeState,
]

class ActionError:
    __hash__: ClassVar[None]  # type: ignore
    index: Optional[int]
    kind: ActionErrorKind
    def __init__(self, index: Optional[int], kind: ActionErrorKind) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "ActionError": ...
    @staticmethod
    def from_json(raw: str) -> "ActionError": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class ActionsValidationErrorFieldless:
    DeleteActionMustBeFinal: ClassVar["ActionsValidationErrorFieldless"]
    FunctionCallZeroAttachedGas: ClassVar["ActionsValidationErrorFieldless"]
    IntegerOverflow: ClassVar["ActionsValidationErrorFieldless"]
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __int__(self) -> int: ...

class ActorNoPermission:
    account_id: AccountId
    actor_id: AccountId
    def __init__(self, account_id: AccountId, actor_id: AccountId) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "ActorNoPermission": ...
    @staticmethod
    def from_json(raw: str) -> "ActorNoPermission": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class AddKeyAlreadyExists:
    account_id: AccountId
    public_key: PublicKey
    def __init__(self, account_id: AccountId, public_key: PublicKey) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "AddKeyAlreadyExists": ...
    @staticmethod
    def from_json(raw: str) -> "AddKeyAlreadyExists": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class AddKeyMethodNameLengthExceeded:
    length: int
    limit: int
    def __init__(self, length: int, limit: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "AddKeyMethodNameLengthExceeded": ...
    @staticmethod
    def from_json(raw: str) -> "AddKeyMethodNameLengthExceeded": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class AddKeyMethodNamesNumberOfBytesExceeded:
    limit: int
    total_number_of_bytes: int
    def __init__(self, total_number_of_bytes: int, limit: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "AddKeyMethodNamesNumberOfBytesExceeded": ...
    @staticmethod
    def from_json(raw: str) -> "AddKeyMethodNamesNumberOfBytesExceeded": ...
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

class CreateAccountNotAllowed:
    account_id: AccountId
    predecessor_id: AccountId
    def __init__(self, account_id: AccountId, predecessor_id: AccountId) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "CreateAccountNotAllowed": ...
    @staticmethod
    def from_json(raw: str) -> "CreateAccountNotAllowed": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class CreateAccountOnlyByRegistrar:
    account_id: AccountId
    predecessor_id: AccountId
    registrar_account_id: AccountId
    def __init__(
        self,
        account_id: AccountId,
        registrar_account_id: AccountId,
        predecessor_id: AccountId,
    ) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "CreateAccountOnlyByRegistrar": ...
    @staticmethod
    def from_json(raw: str) -> "CreateAccountOnlyByRegistrar": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class DeleteAccountStaking:
    account_id: AccountId
    def __init__(self, account_id: AccountId) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "DeleteAccountStaking": ...
    @staticmethod
    def from_json(raw: str) -> "DeleteAccountStaking": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class DeleteAccountWithLargeState:
    account_id: AccountId
    def __init__(self, account_id: AccountId) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "DeleteAccountWithLargeState": ...
    @staticmethod
    def from_json(raw: str) -> "DeleteAccountWithLargeState": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class DeleteKeyDoesNotExist:
    account_id: AccountId
    public_key: PublicKey
    def __init__(self, account_id: AccountId, public_key: PublicKey) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "DeleteKeyDoesNotExist": ...
    @staticmethod
    def from_json(raw: str) -> "DeleteKeyDoesNotExist": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class FunctionCallArgumentsLengthExceeded:
    length: int
    limit: int
    def __init__(self, length: int, limit: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "FunctionCallArgumentsLengthExceeded": ...
    @staticmethod
    def from_json(raw: str) -> "FunctionCallArgumentsLengthExceeded": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class FunctionCallMethodNameLengthExceeded:
    length: int
    limit: int
    def __init__(self, length: int, limit: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "FunctionCallMethodNameLengthExceeded": ...
    @staticmethod
    def from_json(raw: str) -> "FunctionCallMethodNameLengthExceeded": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class InsufficientStake:
    account_id: AccountId
    minimum_stake: int
    stake: int
    def __init__(
        self, account_id: AccountId, stake: int, minimum_stake: int
    ) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "InsufficientStake": ...
    @staticmethod
    def from_json(raw: str) -> "InsufficientStake": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class InvalidAccessKeyErrorFieldless:
    DepositWithFunctionCall: ClassVar["InvalidAccessKeyErrorFieldless"]
    RequiresFullAccess: ClassVar["InvalidAccessKeyErrorFieldless"]
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __int__(self) -> int: ...

class InvalidAccountId:
    account_id: str
    def __init__(self, account_id: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "InvalidAccountId": ...
    @staticmethod
    def from_json(raw: str) -> "InvalidAccountId": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class InvalidDataReceiverId:
    account_id: str
    def __init__(self, account_id: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "InvalidDataReceiverId": ...
    @staticmethod
    def from_json(raw: str) -> "InvalidDataReceiverId": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class InvalidNonce:
    ak_nonce: int
    tx_nonce: int
    def __init__(self, tx_nonce: int, ak_nonce: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "InvalidNonce": ...
    @staticmethod
    def from_json(raw: str) -> "InvalidNonce": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class InvalidPredecessorId:
    account_id: str
    def __init__(self, account_id: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "InvalidPredecessorId": ...
    @staticmethod
    def from_json(raw: str) -> "InvalidPredecessorId": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class InvalidReceiverId:
    receiver_id: str
    def __init__(self, receiver_id: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "InvalidReceiverId": ...
    @staticmethod
    def from_json(raw: str) -> "InvalidReceiverId": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class InvalidSignerId:
    signer_id: str
    def __init__(self, signer_id: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "InvalidSignerId": ...
    @staticmethod
    def from_json(raw: str) -> "InvalidSignerId": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class InvalidTxErrorFieldless:
    CostOverflow: ClassVar["InvalidTxErrorFieldless"]
    Expired: ClassVar["InvalidTxErrorFieldless"]
    InvalidChain: ClassVar["InvalidTxErrorFieldless"]
    InvalidSignature: ClassVar["InvalidTxErrorFieldless"]
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __int__(self) -> int: ...

class LackBalanceForState:
    account_id: AccountId
    amount: int
    def __init__(self, account_id: AccountId, amount: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "LackBalanceForState": ...
    @staticmethod
    def from_json(raw: str) -> "LackBalanceForState": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class MethodNameMismatch:
    method_name: str
    def __init__(self, method_name: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "MethodNameMismatch": ...
    @staticmethod
    def from_json(raw: str) -> "MethodNameMismatch": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class NonceTooLarge:
    tx_nonce: int
    upper_bound: int
    def __init__(self, tx_nonce: int, upper_bound: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "NonceTooLarge": ...
    @staticmethod
    def from_json(raw: str) -> "NonceTooLarge": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class NotEnoughAllowance:
    account_id: AccountId
    allowance: int
    cost: int
    public_key: PublicKey
    def __init__(
        self, account_id: AccountId, public_key: PublicKey, allowance: int, cost: int
    ) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "NotEnoughAllowance": ...
    @staticmethod
    def from_json(raw: str) -> "NotEnoughAllowance": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class NotEnoughBalance:
    balance: int
    cost: int
    signer_id: AccountId
    def __init__(self, signer_id: AccountId, balance: int, cost: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "NotEnoughBalance": ...
    @staticmethod
    def from_json(raw: str) -> "NotEnoughBalance": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

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

class OnlyImplicitAccountCreationAllowed:
    account_id: AccountId
    def __init__(self, account_id: AccountId) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "OnlyImplicitAccountCreationAllowed": ...
    @staticmethod
    def from_json(raw: str) -> "OnlyImplicitAccountCreationAllowed": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class ReceiptInvalidReceiverId:
    account_id: str
    def __init__(self, account_id: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "ReceiptInvalidReceiverId": ...
    @staticmethod
    def from_json(raw: str) -> "ReceiptInvalidReceiverId": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class ReceiptInvalidSignerId:
    account_id: str
    def __init__(self, account_id: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "ReceiptInvalidSignerId": ...
    @staticmethod
    def from_json(raw: str) -> "ReceiptInvalidSignerId": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class ReceiverMismatch:
    ak_receiver: str
    tx_receiver: AccountId
    def __init__(self, tx_receiver: AccountId, ak_receiver: str) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "ReceiverMismatch": ...
    @staticmethod
    def from_json(raw: str) -> "ReceiverMismatch": ...
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

class SignerDoesNotExist:
    signer_id: AccountId
    def __init__(self, signer_id: AccountId) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "SignerDoesNotExist": ...
    @staticmethod
    def from_json(raw: str) -> "SignerDoesNotExist": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class TotalNumberOfActionsExceeded:
    limit: int
    total_number_of_actions: int
    def __init__(self, total_number_of_actions: int, limit: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "TotalNumberOfActionsExceeded": ...
    @staticmethod
    def from_json(raw: str) -> "TotalNumberOfActionsExceeded": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class TotalPrepaidGasExceeded:
    limit: int
    total_prepaid_gas: int
    def __init__(self, total_prepaid_gas: int, limit: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "TotalPrepaidGasExceeded": ...
    @staticmethod
    def from_json(raw: str) -> "TotalPrepaidGasExceeded": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class TransactionSizeExceeded:
    limit: int
    size: int
    def __init__(self, size: int, limit: int) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "TransactionSizeExceeded": ...
    @staticmethod
    def from_json(raw: str) -> "TransactionSizeExceeded": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class TriesToStake:
    account_id: AccountId
    balance: int
    locked: int
    stake: int
    def __init__(
        self, account_id: AccountId, stake: int, locked: int, balance: int
    ) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "TriesToStake": ...
    @staticmethod
    def from_json(raw: str) -> "TriesToStake": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class TriesToUnstake:
    account_id: AccountId
    def __init__(self, account_id: AccountId) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "TriesToUnstake": ...
    @staticmethod
    def from_json(raw: str) -> "TriesToUnstake": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

class UnsuitableStakingKey:
    public_key: PublicKey
    def __init__(self, public_key: PublicKey) -> None: ...
    @staticmethod
    def from_bytes(data: bytes) -> "UnsuitableStakingKey": ...
    @staticmethod
    def from_json(raw: str) -> "UnsuitableStakingKey": ...
    def to_json(self) -> str: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __reduce__(self) -> Tuple[Callable, Tuple[bytes]]: ...

ActionsValidationError = Union[
    ActionsValidationErrorFieldless,
    TotalPrepaidGasExceeded,
    TotalNumberOfActionsExceeded,
    AddKeyMethodNamesNumberOfBytesExceeded,
    AddKeyMethodNameLengthExceeded,
    InvalidAccountId,
    ContractSizeExceeded,
    FunctionCallMethodNameLengthExceeded,
    FunctionCallArgumentsLengthExceeded,
    UnsuitableStakingKey,
]

InvalidAccessKeyError = Union[
    InvalidAccessKeyErrorFieldless,
    AccessKeyNotFound,
    ReceiverMismatch,
    MethodNameMismatch,
    NotEnoughAllowance,
]

InvalidTxError = Union[
    InvalidTxErrorFieldless,
    InvalidAccessKeyError,
    InvalidSignerId,
    SignerDoesNotExist,
    InvalidNonce,
    NonceTooLarge,
    InvalidReceiverId,
    NotEnoughBalance,
    LackBalanceForState,
    ActionsValidationError,
    TransactionSizeExceeded,
]

ReceiptValidationError = Union[
    InvalidPredecessorId,
    ReceiptInvalidReceiverId,
    ReceiptInvalidSignerId,
    InvalidDataReceiverId,
    ReturnedValueLengthExceeded,
    NumberInputDataDependenciesExceeded,
    ActionsValidationError,
]

TxExecutionError = Union[ActionError, InvalidTxError]
