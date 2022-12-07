use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{Display, From, Into};
use near_primitives::errors::{
    ActionError as ActionErrorOriginal, ActionErrorKind as ActionErrorKindOriginal,
    ActionsValidationError as ActionsValidationErrorOriginal,
    InvalidAccessKeyError as InvalidAccessKeyErrorOriginal,
    InvalidTxError as InvalidTxErrorOriginal,
    ReceiptValidationError as ReceiptValidationErrorOriginal,
    TxExecutionError as TxExecutionErrorOriginal,
};
use near_primitives::{
    serialize::dec_format,
    types::{Balance, Gas, Nonce},
};
use pyo3::prelude::*;
use pyo3::types::PyType;
use serde::{Deserialize, Serialize};
use solders_macros::{common_methods, richcmp_eq_only, EnumIntoPy};

use crate::error::vm::get_function_call_error_ser_members;
use crate::{account_id::AccountId, crypto::PublicKey};
use crate::{
    add_classes, add_union_to_module, hash_enum, quick_struct_boilerplate,
    quick_struct_boilerplate_core, vec_type_object,
};

use super::vm::FunctionCallErrorSer;
macro_rules! quick_struct_core {
    ($name:ident, $doc:literal, $($element:ident: $ty:ty),*) => {
        $crate::quick_struct!(
            $name,
            $doc,
            "pyonear.error.core",
            $($element:$ty),*
        );
    };
}
macro_rules! quick_struct_core_length_limit {
    ($name:ident, $doc:literal) => {
        $crate::quick_struct_length_limit!($name, $doc, "pyonear.error.core");
    };
}
macro_rules! quick_struct_core_size_limit {
    ($name:ident, $doc:literal) => {
        $crate::quick_struct_size_limit!($name, $doc, "pyonear.error.core");
    };
}
macro_rules! quick_struct_core_method_name {
    ($name:ident, $doc:literal) => {
        quick_struct_core!($name, $doc, method_name: String);
    };
}
macro_rules! quick_struct_core_account_id {
    ($name:ident, $doc:literal) => {
        quick_struct_core!($name, $doc, account_id: AccountId);
    };
}
macro_rules! quick_struct_core_account_id_and_others {
    ($name:ident, $doc:literal, $($element:ident: $ty:ty),*) => {
        quick_struct_core!($name, $doc, account_id: AccountId, $($element:$ty),*);
    };
}
macro_rules! quick_struct_core_account_id_string {
    ($name:ident, $doc:literal) => {
        quick_struct_core!($name, $doc, account_id: String);
    };
}

#[derive(Debug, Clone, PartialEq, Eq, FromPyObject, EnumIntoPy)]
pub enum ActionErrorKind {
    AccountAlreadyExists(AccountAlreadyExists),
    AccountDoesNotExist(AccountDoesNotExist),
    CreateAccountOnlyByRegistrar(CreateAccountOnlyByRegistrar),
    CreateAccountNotAllowed(CreateAccountNotAllowed),
    ActorNoPermission(ActorNoPermission),
    DeleteKeyDoesNotExist(DeleteKeyDoesNotExist),
    AddKeyAlreadyExists(AddKeyAlreadyExists),
    DeleteAccountStaking(DeleteAccountStaking),
    LackBalanceForState(LackBalanceForState),
    TriesToUnstake(TriesToUnstake),
    TriesToStake(TriesToStake),
    InsufficientStake(InsufficientStake),
    FunctionCallError(FunctionCallErrorSer),
    NewReceiptValidationError(ReceiptValidationError),
    OnlyImplicitAccountCreationAllowed(OnlyImplicitAccountCreationAllowed),
    DeleteAccountWithLargeState(DeleteAccountWithLargeState),
}

impl From<ActionErrorKindOriginal> for ActionErrorKind {
    fn from(e: ActionErrorKindOriginal) -> Self {
        type E = ActionErrorKindOriginal;
        match e {
            E::AccountAlreadyExists { account_id } => {
                Self::AccountAlreadyExists(AccountAlreadyExists {
                    account_id: account_id.into(),
                })
            }
            E::AccountDoesNotExist { account_id } => {
                Self::AccountDoesNotExist(AccountDoesNotExist {
                    account_id: account_id.into(),
                })
            }
            E::CreateAccountOnlyByRegistrar {
                account_id,
                registrar_account_id,
                predecessor_id,
            } => Self::CreateAccountOnlyByRegistrar(CreateAccountOnlyByRegistrar {
                account_id: account_id.into(),
                registrar_account_id: registrar_account_id.into(),
                predecessor_id: predecessor_id.into(),
            }),
            E::CreateAccountNotAllowed {
                account_id,
                predecessor_id,
            } => Self::CreateAccountNotAllowed(CreateAccountNotAllowed {
                account_id: account_id.into(),
                predecessor_id: predecessor_id.into(),
            }),
            E::ActorNoPermission {
                account_id,
                actor_id,
            } => Self::ActorNoPermission(ActorNoPermission {
                account_id: account_id.into(),
                actor_id: actor_id.into(),
            }),
            E::DeleteKeyDoesNotExist {
                account_id,
                public_key,
            } => Self::DeleteKeyDoesNotExist(DeleteKeyDoesNotExist {
                account_id: account_id.into(),
                public_key: public_key.into(),
            }),
            E::AddKeyAlreadyExists {
                account_id,
                public_key,
            } => Self::AddKeyAlreadyExists(AddKeyAlreadyExists {
                account_id: account_id.into(),
                public_key: public_key.into(),
            }),
            E::DeleteAccountStaking { account_id } => {
                Self::DeleteAccountStaking(DeleteAccountStaking {
                    account_id: account_id.into(),
                })
            }
            E::LackBalanceForState { account_id, amount } => {
                Self::LackBalanceForState(LackBalanceForState {
                    account_id: account_id.into(),
                    amount,
                })
            }
            E::TriesToUnstake { account_id } => Self::TriesToUnstake(TriesToUnstake {
                account_id: account_id.into(),
            }),
            E::TriesToStake {
                account_id,
                stake,
                locked,
                balance,
            } => Self::TriesToStake(TriesToStake {
                account_id: account_id.into(),
                stake,
                locked,
                balance,
            }),
            E::InsufficientStake {
                account_id,
                stake,
                minimum_stake,
            } => Self::InsufficientStake(InsufficientStake {
                account_id: account_id.into(),
                stake,
                minimum_stake,
            }),
            E::FunctionCallError(x) => Self::FunctionCallError(x.into()),
            E::NewReceiptValidationError(x) => Self::NewReceiptValidationError(x.into()),
            E::OnlyImplicitAccountCreationAllowed { account_id } => {
                Self::OnlyImplicitAccountCreationAllowed(OnlyImplicitAccountCreationAllowed {
                    account_id: account_id.into(),
                })
            }
            E::DeleteAccountWithLargeState { account_id } => {
                Self::DeleteAccountWithLargeState(DeleteAccountWithLargeState {
                    account_id: account_id.into(),
                })
            }
        }
    }
}

impl From<ActionErrorKind> for ActionErrorKindOriginal {
    fn from(e: ActionErrorKind) -> Self {
        type E = ActionErrorKind;
        match e {
            E::AccountAlreadyExists(x) => Self::AccountAlreadyExists {
                account_id: x.account_id.into(),
            },
            E::AccountDoesNotExist(x) => Self::AccountDoesNotExist {
                account_id: x.account_id.into(),
            },
            E::CreateAccountOnlyByRegistrar(x) => Self::CreateAccountOnlyByRegistrar {
                account_id: x.account_id.into(),
                registrar_account_id: x.registrar_account_id.into(),
                predecessor_id: x.predecessor_id.into(),
            },
            E::CreateAccountNotAllowed(x) => Self::CreateAccountNotAllowed {
                account_id: x.account_id.into(),
                predecessor_id: x.predecessor_id.into(),
            },
            E::ActorNoPermission(x) => Self::ActorNoPermission {
                account_id: x.account_id.into(),
                actor_id: x.actor_id.into(),
            },
            E::DeleteKeyDoesNotExist(x) => Self::DeleteKeyDoesNotExist {
                account_id: x.account_id.into(),
                public_key: x.public_key.into(),
            },
            E::AddKeyAlreadyExists(x) => Self::AddKeyAlreadyExists {
                account_id: x.account_id.into(),
                public_key: x.public_key.into(),
            },
            E::DeleteAccountStaking(x) => Self::DeleteAccountStaking {
                account_id: x.account_id.into(),
            },
            E::LackBalanceForState(x) => Self::LackBalanceForState {
                account_id: x.account_id.into(),
                amount: x.amount,
            },
            E::TriesToUnstake(x) => Self::TriesToUnstake {
                account_id: x.account_id.into(),
            },
            E::TriesToStake(x) => Self::TriesToStake {
                account_id: x.account_id.into(),
                stake: x.stake,
                locked: x.locked,
                balance: x.balance,
            },
            E::InsufficientStake(x) => Self::InsufficientStake {
                account_id: x.account_id.into(),
                stake: x.stake,
                minimum_stake: x.minimum_stake,
            },
            E::FunctionCallError(x) => Self::FunctionCallError(x.into()),
            E::NewReceiptValidationError(x) => Self::NewReceiptValidationError(x.into()),
            E::OnlyImplicitAccountCreationAllowed(x) => Self::OnlyImplicitAccountCreationAllowed {
                account_id: x.account_id.into(),
            },
            E::DeleteAccountWithLargeState(x) => Self::DeleteAccountWithLargeState {
                account_id: x.account_id.into(),
            },
        }
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[pyclass(module = "pyonear.error.core", subclass, get_all)]
pub struct InsufficientStake {
    account_id: AccountId,
    #[serde(with = "dec_format")]
    stake: Balance,
    #[serde(with = "dec_format")]
    minimum_stake: Balance,
}
#[solders_macros::common_methods]
#[solders_macros::pyhash]
#[solders_macros::richcmp_eq_only]
#[pymethods]
impl InsufficientStake {
    #[new]
    pub fn new(account_id: AccountId, stake: Balance, minimum_stake: Balance) -> Self {
        Self {
            account_id,
            stake,
            minimum_stake,
        }
    }
}
quick_struct_boilerplate!(InsufficientStake);
/// The account doesn't have enough balance to increase the stake.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[pyclass(module = "pyonear.error.core", subclass, get_all)]
pub struct TriesToStake {
    account_id: AccountId,
    #[serde(with = "dec_format")]
    stake: Balance,
    #[serde(with = "dec_format")]
    locked: Balance,
    #[serde(with = "dec_format")]
    balance: Balance,
}
#[solders_macros::common_methods]
#[solders_macros::pyhash]
#[solders_macros::richcmp_eq_only]
#[pymethods]
impl TriesToStake {
    #[new]
    pub fn new(account_id: AccountId, stake: Balance, locked: Balance, balance: Balance) -> Self {
        Self {
            account_id,
            stake,
            locked,
            balance,
        }
    }
}
quick_struct_boilerplate!(TriesToStake);
quick_struct_core_account_id!(AccountAlreadyExists, "Happens when CreateAccount action tries to create an account with account_id which is already exists in the storage");
quick_struct_core_account_id!(
    AccountDoesNotExist,
    "Happens when TX receiver_id doesn't exist (but action is not Action::CreateAccount)"
);
quick_struct_core_account_id_and_others!(
    CreateAccountOnlyByRegistrar,
    "A top-level account ID can only be created by registrar.",
    registrar_account_id: AccountId,
    predecessor_id: AccountId
);
quick_struct_core_account_id_and_others!(
    CreateAccountNotAllowed,
    "A newly created account must be under a namespace of the creator account",
    predecessor_id: AccountId
);
quick_struct_core_account_id_and_others!(ActorNoPermission, "Administrative actions like ``DeployContract``, ``Stake``, ``AddKey``, ``DeleteKey``. can be proceed only if sender=receiver or the first TX action is a ``CreateAccount`` action",actor_id: AccountId);
quick_struct_core_account_id_and_others!(
    DeleteKeyDoesNotExist,
    "Account tries to remove an access key that doesn't exist",
    public_key: PublicKey
);
quick_struct_core_account_id_and_others!(
    AddKeyAlreadyExists,
    "The public key is already used for an existing access key",
    public_key: PublicKey
);
quick_struct_core_account_id!(
    DeleteAccountStaking,
    "Account is staking and can not be deleted"
);
quick_struct_core_account_id!(OnlyImplicitAccountCreationAllowed, "Error occurs when a ``CreateAccount`` action is called on hex-characters account of length 64.  See implicit account creation NEP: <https://github.com/nearprotocol/NEPs/pull/71>.");
quick_struct_core_account_id!(
    DeleteAccountWithLargeState,
    "Delete account whose state is large is temporarily banned."
);
quick_struct_core_account_id!(
    TriesToUnstake,
    "Account is not yet staked, but tries to unstake"
);

#[derive(Debug, Clone, PartialEq, Eq, FromPyObject, EnumIntoPy)]
pub enum ReceiptValidationError {
    InvalidPredecessorId(InvalidPredecessorId),
    InvalidReceiverId(ReceiptInvalidReceiverId),
    InvalidSignerId(ReceiptInvalidSignerId),
    InvalidDataReceiverId(InvalidDataReceiverId),
    ReturnedValueLengthExceeded(ReturnedValueLengthExceeded),
    NumberInputDataDependenciesExceeded(NumberInputDataDependenciesExceeded),
    ActionsValidation(ActionsValidationError),
}

impl From<ReceiptValidationError> for ReceiptValidationErrorOriginal {
    fn from(e: ReceiptValidationError) -> Self {
        type E = ReceiptValidationError;
        match e {
            E::InvalidPredecessorId(x) => Self::InvalidPredecessorId {
                account_id: x.account_id,
            },
            E::InvalidReceiverId(x) => Self::InvalidReceiverId {
                account_id: x.account_id,
            },
            E::InvalidSignerId(x) => Self::InvalidSignerId {
                account_id: x.account_id,
            },
            E::InvalidDataReceiverId(x) => Self::InvalidDataReceiverId {
                account_id: x.account_id,
            },
            E::ReturnedValueLengthExceeded(x) => Self::ReturnedValueLengthExceeded {
                length: x.length,
                limit: x.limit,
            },
            E::NumberInputDataDependenciesExceeded(x) => {
                Self::NumberInputDataDependenciesExceeded {
                    number_of_input_data_dependencies: x.number_of_input_data_dependencies,
                    limit: x.limit,
                }
            }
            E::ActionsValidation(x) => Self::ActionsValidation(x.into()),
        }
    }
}

impl From<ReceiptValidationErrorOriginal> for ReceiptValidationError {
    fn from(e: ReceiptValidationErrorOriginal) -> Self {
        type E = ReceiptValidationErrorOriginal;
        match e {
            E::InvalidPredecessorId { account_id } => {
                Self::InvalidPredecessorId(InvalidPredecessorId { account_id })
            }
            E::InvalidReceiverId { account_id } => {
                Self::InvalidReceiverId(ReceiptInvalidReceiverId { account_id })
            }
            E::InvalidSignerId { account_id } => {
                Self::InvalidSignerId(ReceiptInvalidSignerId { account_id })
            }
            E::InvalidDataReceiverId { account_id } => {
                Self::InvalidDataReceiverId(InvalidDataReceiverId { account_id })
            }
            E::ReturnedValueLengthExceeded { length, limit } => {
                Self::ReturnedValueLengthExceeded(ReturnedValueLengthExceeded { length, limit })
            }
            E::NumberInputDataDependenciesExceeded {
                number_of_input_data_dependencies,
                limit,
            } => Self::NumberInputDataDependenciesExceeded(NumberInputDataDependenciesExceeded {
                number_of_input_data_dependencies,
                limit,
            }),
            E::ActionsValidation(x) => Self::ActionsValidation(x.into()),
        }
    }
}

quick_struct_core_account_id_string!(
    InvalidPredecessorId,
    "The ``predecessor_id`` of a Receipt is not valid."
);
quick_struct_core_account_id_string!(
    ReceiptInvalidReceiverId,
    "The `receiver_id` of a Receipt is not valid."
);
quick_struct_core_account_id_string!(
    ReceiptInvalidSignerId,
    "The `signer_id` of an ActionReceipt is not valid."
);
quick_struct_core_account_id_string!(
    InvalidDataReceiverId,
    "The length of the returned data exceeded the limit in a DataReceipt."
);
quick_struct_core_length_limit!(
    ReturnedValueLengthExceeded,
    "The length of the returned data exceeded the limit in a DataReceipt."
);
quick_struct_core!(
    NumberInputDataDependenciesExceeded,
    "The number of input data dependencies exceeds the limit in an ActionReceipt.",
    number_of_input_data_dependencies: u64,
    limit: u64
);

/// Happens if a wrong AccessKey used or AccessKey has not enough permissions
#[pyclass(module = "pyonear.error.core")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InvalidAccessKeyErrorFieldless {
    /// Having a deposit with a function call action is not allowed with a function call access key.
    DepositWithFunctionCall,
    /// Transaction requires a full permission access key.
    RequiresFullAccess,
}
hash_enum!(InvalidAccessKeyErrorFieldless);

#[derive(Debug, Clone, PartialEq, Eq, FromPyObject, EnumIntoPy)]
pub enum InvalidAccessKeyError {
    Fieldless(InvalidAccessKeyErrorFieldless),
    AccessKeyNotFound(AccessKeyNotFound),
    ReceiverMismatch(ReceiverMismatch),
    MethodNameMismatch(MethodNameMismatch),
    NotEnoughAllowance(NotEnoughAllowance),
}
impl From<InvalidAccessKeyError> for InvalidAccessKeyErrorOriginal {
    fn from(e: InvalidAccessKeyError) -> Self {
        type E = InvalidAccessKeyError;
        match e {
            E::Fieldless(x) => match x {
                InvalidAccessKeyErrorFieldless::DepositWithFunctionCall => {
                    Self::DepositWithFunctionCall
                }
                InvalidAccessKeyErrorFieldless::RequiresFullAccess => Self::RequiresFullAccess,
            },
            E::AccessKeyNotFound(x) => Self::AccessKeyNotFound {
                account_id: x.account_id.into(),
                public_key: x.public_key.into(),
            },
            E::ReceiverMismatch(x) => Self::ReceiverMismatch {
                tx_receiver: x.tx_receiver.into(),
                ak_receiver: x.ak_receiver,
            },
            E::MethodNameMismatch(x) => Self::MethodNameMismatch {
                method_name: x.method_name,
            },
            E::NotEnoughAllowance(x) => Self::NotEnoughAllowance {
                account_id: x.account_id.into(),
                public_key: x.public_key.into(),
                allowance: x.allowance,
                cost: x.cost,
            },
        }
    }
}
impl From<InvalidAccessKeyErrorOriginal> for InvalidAccessKeyError {
    fn from(e: InvalidAccessKeyErrorOriginal) -> Self {
        type E = InvalidAccessKeyErrorOriginal;
        match e {
            E::DepositWithFunctionCall => {
                Self::Fieldless(InvalidAccessKeyErrorFieldless::DepositWithFunctionCall)
            }
            E::RequiresFullAccess => {
                Self::Fieldless(InvalidAccessKeyErrorFieldless::RequiresFullAccess)
            }
            E::AccessKeyNotFound {
                account_id,
                public_key,
            } => Self::AccessKeyNotFound(AccessKeyNotFound {
                account_id: account_id.into(),
                public_key: public_key.into(),
            }),
            E::ReceiverMismatch {
                tx_receiver,
                ak_receiver,
            } => Self::ReceiverMismatch(ReceiverMismatch {
                tx_receiver: tx_receiver.into(),
                ak_receiver,
            }),
            E::MethodNameMismatch { method_name } => {
                Self::MethodNameMismatch(MethodNameMismatch { method_name })
            }
            E::NotEnoughAllowance {
                account_id,
                public_key,
                allowance,
                cost,
            } => Self::NotEnoughAllowance(NotEnoughAllowance {
                account_id: account_id.into(),
                public_key: public_key.into(),
                allowance,
                cost,
            }),
        }
    }
}

quick_struct_core!(
    AccessKeyNotFound,
    "The access key identified by the ``public_key`` doesn't exist for the account",
    account_id: AccountId,
    public_key: PublicKey
);
quick_struct_core!(
    ReceiverMismatch,
    "Transaction `receiver_id` doesn't match the access key receiver_id",
    tx_receiver: AccountId,
    ak_receiver: String
);
quick_struct_core_method_name!(
    MethodNameMismatch,
    "Transaction method name isn't allowed by the access key"
);
/// Access Key does not have enough allowance to cover transaction cost
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[pyclass(module = "pyonear.error.core", subclass, get_all)]
pub struct NotEnoughAllowance {
    pub account_id: AccountId,
    pub public_key: PublicKey,
    #[serde(with = "dec_format")]
    pub allowance: Balance,
    #[serde(with = "dec_format")]
    pub cost: Balance,
}
#[solders_macros::common_methods]
#[solders_macros::pyhash]
#[solders_macros::richcmp_eq_only]
#[pymethods]
impl NotEnoughAllowance {
    #[new]
    pub fn new(
        account_id: AccountId,
        public_key: PublicKey,
        allowance: Balance,
        cost: Balance,
    ) -> Self {
        Self {
            account_id,
            public_key,
            allowance,
            cost,
        }
    }
}
quick_struct_boilerplate!(NotEnoughAllowance);

/// An error happened during TX execution
#[derive(Debug, Clone, PartialEq, Eq, FromPyObject, EnumIntoPy)]
pub enum InvalidTxError {
    Fieldless(InvalidTxErrorFieldless),
    InvalidAccessKeyError(InvalidAccessKeyError),
    InvalidSignerId(InvalidSignerId),
    SignerDoesNotExist(SignerDoesNotExist),
    InvalidNonce(InvalidNonce),
    NonceTooLarge(NonceTooLarge),
    InvalidReceiverId(InvalidReceiverId),
    NotEnoughBalance(NotEnoughBalance),
    LackBalanceForState(LackBalanceForState),
    ActionsValidation(ActionsValidationError),
    TransactionSizeExceeded(TransactionSizeExceeded),
}
impl From<InvalidTxError> for InvalidTxErrorOriginal {
    fn from(e: InvalidTxError) -> Self {
        type E = InvalidTxError;
        match e {
            E::Fieldless(x) => match x {
                InvalidTxErrorFieldless::InvalidSignature => Self::InvalidSignature,
                InvalidTxErrorFieldless::CostOverflow => Self::CostOverflow,
                InvalidTxErrorFieldless::InvalidChain => Self::InvalidChain,
                InvalidTxErrorFieldless::Expired => Self::Expired,
            },
            E::InvalidAccessKeyError(x) => Self::InvalidAccessKeyError(x.into()),
            E::InvalidSignerId(x) => Self::InvalidSignerId {
                signer_id: x.signer_id,
            },
            E::SignerDoesNotExist(x) => Self::SignerDoesNotExist {
                signer_id: x.signer_id.into(),
            },
            E::InvalidNonce(x) => Self::InvalidNonce {
                tx_nonce: x.tx_nonce,
                ak_nonce: x.ak_nonce,
            },
            E::NonceTooLarge(x) => Self::NonceTooLarge {
                tx_nonce: x.tx_nonce,
                upper_bound: x.upper_bound,
            },
            E::InvalidReceiverId(x) => Self::InvalidReceiverId {
                receiver_id: x.receiver_id,
            },
            E::NotEnoughBalance(x) => Self::NotEnoughBalance {
                signer_id: x.signer_id.into(),
                balance: x.balance,
                cost: x.cost,
            },
            E::LackBalanceForState(x) => Self::LackBalanceForState {
                signer_id: x.account_id.into(),
                amount: x.amount,
            },
            E::ActionsValidation(x) => Self::ActionsValidation(x.into()),
            E::TransactionSizeExceeded(x) => Self::TransactionSizeExceeded {
                size: x.size,
                limit: x.limit,
            },
        }
    }
}
impl From<InvalidTxErrorOriginal> for InvalidTxError {
    fn from(e: InvalidTxErrorOriginal) -> Self {
        type E = InvalidTxErrorOriginal;
        match e {
            E::InvalidSignature => Self::Fieldless(InvalidTxErrorFieldless::InvalidSignature),
            E::CostOverflow => Self::Fieldless(InvalidTxErrorFieldless::CostOverflow),
            E::InvalidChain => Self::Fieldless(InvalidTxErrorFieldless::InvalidChain),
            E::Expired => Self::Fieldless(InvalidTxErrorFieldless::Expired),
            E::InvalidAccessKeyError(x) => Self::InvalidAccessKeyError(x.into()),
            E::InvalidSignerId { signer_id } => {
                Self::InvalidSignerId(InvalidSignerId { signer_id })
            }
            E::SignerDoesNotExist { signer_id } => Self::SignerDoesNotExist(SignerDoesNotExist {
                signer_id: signer_id.into(),
            }),
            E::InvalidNonce { tx_nonce, ak_nonce } => {
                Self::InvalidNonce(InvalidNonce { tx_nonce, ak_nonce })
            }
            E::NonceTooLarge {
                tx_nonce,
                upper_bound,
            } => Self::NonceTooLarge(NonceTooLarge {
                tx_nonce,
                upper_bound,
            }),
            E::InvalidReceiverId { receiver_id } => {
                Self::InvalidReceiverId(InvalidReceiverId { receiver_id })
            }
            E::NotEnoughBalance {
                signer_id,
                balance,
                cost,
            } => Self::NotEnoughBalance(NotEnoughBalance {
                signer_id: signer_id.into(),
                balance,
                cost,
            }),
            E::LackBalanceForState { signer_id, amount } => {
                Self::LackBalanceForState(LackBalanceForState {
                    account_id: signer_id.into(),
                    amount,
                })
            }
            E::ActionsValidation(x) => Self::ActionsValidation(x.into()),
            E::TransactionSizeExceeded { size, limit } => {
                Self::TransactionSizeExceeded(TransactionSizeExceeded { size, limit })
            }
        }
    }
}

/// Account does not have enough balance to cover TX cost
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[pyclass(module = "pyonear.error.core", subclass, get_all)]
pub struct NotEnoughBalance {
    pub signer_id: AccountId,
    #[serde(with = "dec_format")]
    pub balance: Balance,
    #[serde(with = "dec_format")]
    pub cost: Balance,
}
#[solders_macros::common_methods]
#[solders_macros::pyhash]
#[solders_macros::richcmp_eq_only]
#[pymethods]
impl NotEnoughBalance {
    #[new]
    pub fn new(signer_id: AccountId, balance: Balance, cost: Balance) -> Self {
        Self {
            signer_id,
            balance,
            cost,
        }
    }
}
quick_struct_boilerplate!(NotEnoughBalance);

/// Signer account doesn't have enough balance after transaction.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[pyclass(module = "pyonear.error.core", subclass, get_all)]
pub struct LackBalanceForState {
    /// An account which doesn't have enough balance to cover storage.
    pub account_id: AccountId,
    /// Required balance to cover the state.
    #[serde(with = "dec_format")]
    pub amount: Balance,
}
#[solders_macros::common_methods]
#[solders_macros::pyhash]
#[solders_macros::richcmp_eq_only]
#[pymethods]
impl LackBalanceForState {
    #[new]
    pub fn new(account_id: AccountId, amount: Balance) -> Self {
        Self { account_id, amount }
    }
}
quick_struct_boilerplate!(LackBalanceForState);
quick_struct_core!(
    InvalidSignerId,
    "TX signer_id is not a valid ``AccountId``",
    signer_id: String
);
quick_struct_core!(
    SignerDoesNotExist,
    "TX signer_id is not found in a storage",
    signer_id: AccountId
);
quick_struct_core!(
    InvalidNonce,
    "Transaction nonce must be `account[access_key].nonce + 1`.",
    tx_nonce: Nonce,
    ak_nonce: Nonce
);
quick_struct_core!(
    NonceTooLarge,
    "Transaction nonce is larger than the upper bound given by the block height",
    tx_nonce: Nonce,
    upper_bound: Nonce
);
quick_struct_core!(
    InvalidReceiverId,
    "TX receiver_id is not a valid AccountId",
    receiver_id: String
);
quick_struct_core_size_limit!(
    TransactionSizeExceeded,
    "The size of serialized transaction exceeded the limit."
);

#[pyclass(module = "pyonear.error.core")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InvalidTxErrorFieldless {
    /// TX signature is not valid
    InvalidSignature,
    /// An integer overflow occurred during transaction cost estimation.
    CostOverflow,
    /// Transaction parent block hash doesn't belong to the current chain
    InvalidChain,
    /// Transaction has expired
    Expired,
}
hash_enum!(InvalidTxErrorFieldless);

#[pyclass(module = "pyonear.error.core")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ActionsValidationErrorFieldless {
    /// The delete action must be a final aciton in transaction
    DeleteActionMustBeFinal,
    /// Integer overflow during a compute.
    IntegerOverflow,
    /// The attached amount of gas in a FunctionCall action has to be a positive number.
    FunctionCallZeroAttachedGas,
}
hash_enum!(ActionsValidationErrorFieldless);

#[derive(PartialEq, Eq, Clone, Debug, FromPyObject, EnumIntoPy)]
pub enum ActionsValidationError {
    Fieldless(ActionsValidationErrorFieldless),
    TotalPrepaidGasExceeded(TotalPrepaidGasExceeded),
    TotalNumberOfActionsExceeded(TotalNumberOfActionsExceeded),
    AddKeyMethodNamesNumberOfBytesExceeded(AddKeyMethodNamesNumberOfBytesExceeded),
    AddKeyMethodNameLengthExceeded(AddKeyMethodNameLengthExceeded),
    InvalidAccountId(InvalidAccountId),
    ContractSizeExceeded(ContractSizeExceeded),
    FunctionCallMethodNameLengthExceeded(FunctionCallMethodNameLengthExceeded),
    FunctionCallArgumentsLengthExceeded(FunctionCallArgumentsLengthExceeded),
    UnsuitableStakingKey(UnsuitableStakingKey),
}
quick_struct_core!(
    TotalPrepaidGasExceeded,
    "The total prepaid gas (for all given actions) exceeded the limit.",
    total_prepaid_gas: Gas,
    limit: Gas
);
quick_struct_core!(
    TotalNumberOfActionsExceeded,
    "The number of actions exceeded the given limit.",
    total_number_of_actions: u64,
    limit: u64
);
quick_struct_core!(
    AddKeyMethodNamesNumberOfBytesExceeded,
    "The total number of bytes of the method names exceeded the limit in a Add Key action.",
    total_number_of_bytes: u64,
    limit: u64
);
quick_struct_core_account_id_string!(InvalidAccountId, "Invalid account ID.");
quick_struct_core!(
    ContractSizeExceeded,
    "The size of the contract code exceeded the limit in a DeployContract action.",
    size: u64,
    limit: u64
);
quick_struct_core_length_limit!(
    FunctionCallArgumentsLengthExceeded,
    "The length of the arguments exceeded the limit in a Function Call action."
);
quick_struct_core_length_limit!(
    AddKeyMethodNameLengthExceeded,
    "The length of some method name exceeded the limit in a Add Key action."
);
quick_struct_core_length_limit!(
    FunctionCallMethodNameLengthExceeded,
    "The length of the method name exceeded the limit in a Function Call action."
);
quick_struct_core!(
    UnsuitableStakingKey,
    "An attempt to stake with a public key that is not convertible to ristretto.",
    public_key: PublicKey
);

impl From<ActionsValidationError> for ActionsValidationErrorOriginal {
    fn from(e: ActionsValidationError) -> Self {
        type E = ActionsValidationError;
        type F = ActionsValidationErrorFieldless;
        match e {
            E::Fieldless(x) => match x {
                F::DeleteActionMustBeFinal => Self::DeleteActionMustBeFinal,
                F::FunctionCallZeroAttachedGas => Self::FunctionCallZeroAttachedGas,
                F::IntegerOverflow => Self::IntegerOverflow,
            },
            E::TotalPrepaidGasExceeded(x) => Self::TotalPrepaidGasExceeded {
                limit: x.limit,
                total_prepaid_gas: x.total_prepaid_gas,
            },
            E::TotalNumberOfActionsExceeded(x) => Self::TotalNumberOfActionsExceeded {
                total_number_of_actions: x.total_number_of_actions,
                limit: x.limit,
            },
            E::AddKeyMethodNamesNumberOfBytesExceeded(x) => {
                Self::AddKeyMethodNamesNumberOfBytesExceeded {
                    total_number_of_bytes: x.total_number_of_bytes,
                    limit: x.limit,
                }
            }
            E::AddKeyMethodNameLengthExceeded(x) => Self::AddKeyMethodNameLengthExceeded {
                length: x.length,
                limit: x.limit,
            },
            E::InvalidAccountId(x) => Self::InvalidAccountId {
                account_id: x.account_id,
            },
            E::ContractSizeExceeded(x) => Self::ContractSizeExceeded {
                size: x.size,
                limit: x.limit,
            },
            E::FunctionCallMethodNameLengthExceeded(x) => {
                Self::FunctionCallMethodNameLengthExceeded {
                    length: x.length,
                    limit: x.limit,
                }
            }
            E::FunctionCallArgumentsLengthExceeded(x) => {
                Self::FunctionCallArgumentsLengthExceeded {
                    length: x.length,
                    limit: x.limit,
                }
            }
            E::UnsuitableStakingKey(x) => Self::UnsuitableStakingKey {
                public_key: x.public_key.into(),
            },
        }
    }
}

impl From<ActionsValidationErrorOriginal> for ActionsValidationError {
    fn from(e: ActionsValidationErrorOriginal) -> Self {
        type E = ActionsValidationErrorOriginal;
        type F = ActionsValidationErrorFieldless;
        match e {
            E::DeleteActionMustBeFinal => Self::Fieldless(F::DeleteActionMustBeFinal),
            E::IntegerOverflow => Self::Fieldless(F::IntegerOverflow),
            E::FunctionCallZeroAttachedGas => Self::Fieldless(F::FunctionCallZeroAttachedGas),
            E::TotalPrepaidGasExceeded {
                total_prepaid_gas,
                limit,
            } => Self::TotalPrepaidGasExceeded(TotalPrepaidGasExceeded {
                total_prepaid_gas,
                limit,
            }),
            E::TotalNumberOfActionsExceeded {
                total_number_of_actions,
                limit,
            } => Self::TotalNumberOfActionsExceeded(TotalNumberOfActionsExceeded {
                total_number_of_actions,
                limit,
            }),
            E::AddKeyMethodNamesNumberOfBytesExceeded {
                total_number_of_bytes,
                limit,
            } => Self::AddKeyMethodNamesNumberOfBytesExceeded(
                AddKeyMethodNamesNumberOfBytesExceeded {
                    total_number_of_bytes,
                    limit,
                },
            ),
            E::AddKeyMethodNameLengthExceeded { length, limit } => {
                Self::AddKeyMethodNameLengthExceeded(AddKeyMethodNameLengthExceeded {
                    length,
                    limit,
                })
            }
            E::InvalidAccountId { account_id } => {
                Self::InvalidAccountId(InvalidAccountId { account_id })
            }
            E::ContractSizeExceeded { size, limit } => {
                Self::ContractSizeExceeded(ContractSizeExceeded { size, limit })
            }
            E::FunctionCallMethodNameLengthExceeded { length, limit } => {
                Self::FunctionCallMethodNameLengthExceeded(FunctionCallMethodNameLengthExceeded {
                    length,
                    limit,
                })
            }
            E::FunctionCallArgumentsLengthExceeded { length, limit } => {
                Self::FunctionCallArgumentsLengthExceeded(FunctionCallArgumentsLengthExceeded {
                    length,
                    limit,
                })
            }
            E::UnsuitableStakingKey { public_key } => {
                Self::UnsuitableStakingKey(UnsuitableStakingKey {
                    public_key: public_key.into(),
                })
            }
        }
    }
}

/// An error happened during Acton execution
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Deserialize,
    Serialize,
    From,
    Into,
    Display,
)]
#[pyclass(module = "pyonear.error", subclass)]
pub struct ActionError(pub ActionErrorOriginal);

#[common_methods]
#[richcmp_eq_only]
#[pymethods]
impl ActionError {
    #[new]
    pub fn new(index: Option<u64>, kind: ActionErrorKind) -> Self {
        ActionErrorOriginal {
            index,
            kind: kind.into(),
        }
        .into()
    }

    /// Index of the failed action in the transaction.
    /// Action index is not defined if ActionError.kind is ``ActionErrorKind::LackBalanceForState``
    #[getter]
    pub fn index(&self) -> Option<u64> {
        self.0.index
    }

    /// The kind of ActionError happened
    #[getter]
    pub fn kind(&self) -> ActionErrorKind {
        self.0.kind.clone().into()
    }
}
quick_struct_boilerplate_core!(ActionError);

/// Error returned in the ExecutionOutcome in case of failure
#[derive(Debug, Clone, PartialEq, Eq, FromPyObject, EnumIntoPy)]
pub enum TxExecutionError {
    ActionError(ActionError),
    InvalidTxError(InvalidTxError),
}

impl From<TxExecutionError> for TxExecutionErrorOriginal {
    fn from(e: TxExecutionError) -> Self {
        match e {
            TxExecutionError::ActionError(x) => Self::ActionError(x.into()),
            TxExecutionError::InvalidTxError(x) => Self::InvalidTxError(x.into()),
        }
    }
}

impl From<TxExecutionErrorOriginal> for TxExecutionError {
    fn from(e: TxExecutionErrorOriginal) -> Self {
        match e {
            TxExecutionErrorOriginal::ActionError(x) => Self::ActionError(x.into()),
            TxExecutionErrorOriginal::InvalidTxError(x) => Self::InvalidTxError(x.into()),
        }
    }
}

fn get_invalid_access_key_error_members(py: Python) -> Vec<&PyType> {
    vec_type_object!(
        py,
        InvalidAccessKeyErrorFieldless,
        AccessKeyNotFound,
        ReceiverMismatch,
        MethodNameMismatch,
        NotEnoughAllowance
    )
}

fn get_actions_validation_error_members(py: Python) -> Vec<&PyType> {
    vec_type_object!(
        py,
        ActionsValidationErrorFieldless,
        TotalPrepaidGasExceeded,
        TotalNumberOfActionsExceeded,
        AddKeyMethodNamesNumberOfBytesExceeded,
        AddKeyMethodNameLengthExceeded,
        InvalidAccountId,
        ContractSizeExceeded,
        FunctionCallMethodNameLengthExceeded,
        FunctionCallArgumentsLengthExceeded,
        UnsuitableStakingKey
    )
}

fn get_invalid_tx_error_members(py: Python) -> Vec<&PyType> {
    let mut base = vec_type_object!(
        py,
        InvalidTxErrorFieldless,
        InvalidSignerId,
        SignerDoesNotExist,
        InvalidNonce,
        NonceTooLarge,
        InvalidReceiverId,
        NotEnoughBalance,
        LackBalanceForState,
        TransactionSizeExceeded
    );
    base.extend(&get_invalid_access_key_error_members(py));
    base.extend(&get_actions_validation_error_members(py));
    base
}

pub(crate) fn get_tx_execution_error_members(py: Python) -> Vec<&PyType> {
    let mut base = vec_type_object!(py, ActionError);
    base.extend(get_invalid_tx_error_members(py));
    base
}

pub(crate) fn create_core_mod(py: Python<'_>) -> PyResult<&PyModule> {
    let m = PyModule::new(py, "core")?;
    add_classes!(
        m,
        ActionsValidationErrorFieldless,
        TotalPrepaidGasExceeded,
        TotalNumberOfActionsExceeded,
        AddKeyMethodNamesNumberOfBytesExceeded,
        AddKeyMethodNameLengthExceeded,
        InvalidAccountId,
        ContractSizeExceeded,
        FunctionCallMethodNameLengthExceeded,
        FunctionCallArgumentsLengthExceeded,
        UnsuitableStakingKey
    );
    let actions_validation_error_members = get_actions_validation_error_members(py);
    add_union_to_module(
        "ActionsValidationError",
        m,
        py,
        actions_validation_error_members.clone(),
    )?;
    add_classes!(
        m,
        InvalidPredecessorId,
        ReceiptInvalidReceiverId,
        ReceiptInvalidSignerId,
        InvalidDataReceiverId,
        ReturnedValueLengthExceeded,
        NumberInputDataDependenciesExceeded
    );
    let mut receipt_validation_error_members = vec_type_object!(
        py,
        InvalidPredecessorId,
        ReceiptInvalidReceiverId,
        ReceiptInvalidSignerId,
        InvalidDataReceiverId,
        ReturnedValueLengthExceeded,
        NumberInputDataDependenciesExceeded
    );
    receipt_validation_error_members.extend(actions_validation_error_members.clone());
    add_union_to_module(
        "ReceiptValidationError",
        m,
        py,
        receipt_validation_error_members.clone(),
    )?;
    add_classes!(
        m,
        InvalidAccessKeyErrorFieldless,
        AccessKeyNotFound,
        ReceiverMismatch,
        MethodNameMismatch,
        NotEnoughAllowance
    );
    let invalid_access_key_error_members = get_invalid_access_key_error_members(py);
    add_union_to_module(
        "InvalidAccessKeyError",
        m,
        py,
        invalid_access_key_error_members.clone(),
    )?;
    add_classes!(
        m,
        InvalidTxErrorFieldless,
        InvalidSignerId,
        SignerDoesNotExist,
        InvalidNonce,
        NonceTooLarge,
        InvalidReceiverId,
        NotEnoughBalance,
        LackBalanceForState,
        TransactionSizeExceeded
    );
    let invalid_tx_error_members = get_invalid_tx_error_members(py);
    add_union_to_module("InvalidTxError", m, py, invalid_tx_error_members.clone())?;
    add_classes!(
        m,
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
        OnlyImplicitAccountCreationAllowed,
        DeleteAccountWithLargeState
    );
    let mut action_error_kind_members = vec_type_object!(
        py,
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
        OnlyImplicitAccountCreationAllowed,
        DeleteAccountWithLargeState
    );
    action_error_kind_members.extend(get_function_call_error_ser_members(py));
    action_error_kind_members.extend(receipt_validation_error_members);
    add_union_to_module("ActionErrorKind", m, py, action_error_kind_members)?;
    m.add_class::<ActionError>()?;
    let tx_execution_error_members = get_tx_execution_error_members(py);
    add_union_to_module("TxExecutionError", m, py, tx_execution_error_members)?;
    Ok(m)
}
