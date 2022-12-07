use crate::{
    account_id::AccountId, add_classes, add_union, add_union_to_module, hash_enum, vec_type_object,
};
use derive_more::From;
use near_vm_errors::{
    CacheError as CacheErrorOriginal, CompilationError as CompilationErrorOriginal,
    FunctionCallErrorSer as FunctionCallErrorSerOriginal, HostError as HostErrorOriginal,
    MethodResolveError as MethodResolveErrorOriginal, PrepareError as PrepareErrorOriginal,
    WasmTrap as WasmTrapOriginal,
};
use pyo3::types::PyString;
use pyo3::{prelude::*, types::PyType};
use serde::{Deserialize, Serialize};
use solders_macros::{enum_original_mapping, EnumIntoPy};
use std::fmt::{self};

macro_rules! quick_struct_vm {
    ($name:ident, $doc:literal, $($element:ident: $ty:ty),*) => {
        $crate::quick_struct!(
            $name,
            $doc,
            "pyonear.error.vm",
            $($element:$ty),*
        );
    };
}

macro_rules! quick_struct_vm_method_name {
    ($name:ident, $doc:literal) => {
        quick_struct_vm!($name, $doc, method_name: String);
    };
}

macro_rules! quick_struct_vm_msg {
    ($name:ident, $doc:literal) => {
        quick_struct_vm!($name, $doc, msg: String);
    };
}
macro_rules! quick_struct_vm_length_limit {
    ($name:ident, $doc:literal) => {
        $crate::quick_struct_length_limit!($name, $doc, "pyonear.error.vm");
    };
}
macro_rules! quick_struct_vm_size_limit {
    ($name:ident, $doc:literal) => {
        $crate::quick_struct_size_limit!($name, $doc, "pyonear.error.vm");
    };
}

macro_rules! quick_struct_vm_u64 {
    ($name:ident, $doc:literal, $elem:ident) => {
        quick_struct_vm!($name, $doc, $elem: u64);
    };
}

quick_struct_vm_msg!(LinkError, "Wasm binary env link error");

/// Serializable version of ``FunctionCallError``.
#[derive(PartialEq, Eq, Clone, Debug, FromPyObject, EnumIntoPy)]
pub enum FunctionCallErrorSer {
    Fieldless(FunctionCallErrorSerFieldless),
    CompilationError(CompilationError),
    LinkError(LinkError),
    MethodResolveError(MethodResolveError),
    WasmTrap(WasmTrap),
    HostError(HostError),
    ExecutionError(String),
}

impl From<FunctionCallErrorSer> for FunctionCallErrorSerOriginal {
    fn from(e: FunctionCallErrorSer) -> Self {
        type E = FunctionCallErrorSer;
        match e {
            E::Fieldless(f) => match f {
                FunctionCallErrorSerFieldless::WasmUnknownError => Self::WasmUnknownError,
                FunctionCallErrorSerFieldless::_EVMError => Self::_EVMError,
            },
            E::CompilationError(x) => Self::CompilationError(x.into()),
            E::LinkError(x) => Self::LinkError { msg: x.msg },
            E::MethodResolveError(x) => Self::MethodResolveError(x.into()),
            E::WasmTrap(x) => Self::WasmTrap(x.into()),
            E::HostError(x) => Self::HostError(x.into()),
            E::ExecutionError(x) => Self::ExecutionError(x),
        }
    }
}

impl From<FunctionCallErrorSerOriginal> for FunctionCallErrorSer {
    fn from(e: FunctionCallErrorSerOriginal) -> Self {
        type E = FunctionCallErrorSerOriginal;
        match e {
            E::WasmUnknownError => Self::Fieldless(FunctionCallErrorSerFieldless::WasmUnknownError),
            E::_EVMError => Self::Fieldless(FunctionCallErrorSerFieldless::_EVMError),
            E::CompilationError(x) => Self::CompilationError(x.into()),
            E::LinkError { msg } => Self::LinkError(LinkError { msg }),
            E::MethodResolveError(x) => Self::MethodResolveError(x.into()),
            E::WasmTrap(x) => Self::WasmTrap(x.into()),
            E::HostError(x) => Self::HostError(x.into()),
            E::ExecutionError(x) => Self::ExecutionError(x),
        }
    }
}

#[pyclass(module = "pyonear.error.vm")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FunctionCallErrorSerFieldless {
    WasmUnknownError,
    _EVMError,
}
hash_enum!(FunctionCallErrorSerFieldless);

#[pyclass(module = "pyonear.error.vm")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CacheErrorFieldless {
    ReadError,
    WriteError,
    DeserializationError,
}
hash_enum!(CacheErrorFieldless);

quick_struct_vm!(SerializationError, "", hash: [u8; 32]);

#[derive(PartialEq, Eq, Clone, Debug, FromPyObject, From)]
pub enum CacheError {
    Fieldless(CacheErrorFieldless),
    SerializationError(SerializationError),
}

impl From<CacheError> for CacheErrorOriginal {
    fn from(e: CacheError) -> Self {
        match e {
            CacheError::Fieldless(f) => match f {
                CacheErrorFieldless::ReadError => Self::ReadError,
                CacheErrorFieldless::WriteError => Self::WriteError,
                CacheErrorFieldless::DeserializationError => Self::DeserializationError,
            },
            CacheError::SerializationError(s) => Self::SerializationError { hash: s.hash },
        }
    }
}

impl From<CacheErrorOriginal> for CacheError {
    fn from(e: CacheErrorOriginal) -> Self {
        match e {
            CacheErrorOriginal::ReadError => Self::Fieldless(CacheErrorFieldless::ReadError),
            CacheErrorOriginal::WriteError => Self::Fieldless(CacheErrorFieldless::WriteError),
            CacheErrorOriginal::DeserializationError => {
                Self::Fieldless(CacheErrorFieldless::DeserializationError)
            }
            CacheErrorOriginal::SerializationError { hash } => {
                Self::SerializationError(SerializationError { hash })
            }
        }
    }
}

/// A kind of a trap happened during execution of a binary
#[pyclass(module = "pyonear.error.vm")]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[enum_original_mapping(WasmTrapOriginal)]
pub enum WasmTrap {
    /// An `unreachable` opcode was executed.
    Unreachable,
    /// Call indirect incorrect signature trap.
    IncorrectCallIndirectSignature,
    /// Memory out of bounds trap.
    MemoryOutOfBounds,
    /// Call indirect out of bounds trap.
    CallIndirectOOB,
    /// An arithmetic exception, e.g. divided by zero.
    IllegalArithmetic,
    /// Misaligned atomic access trap.
    MisalignedAtomicAccess,
    /// Indirect call to null.
    IndirectCallToNull,
    /// Stack overflow.
    StackOverflow,
    /// Generic trap.
    GenericTrap,
}
hash_enum!(WasmTrap);

/// Import/export resolve error
#[pyclass(module = "pyonear.error.vm")]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[enum_original_mapping(MethodResolveErrorOriginal)]
pub enum MethodResolveError {
    MethodEmptyName,
    MethodNotFound,
    MethodInvalidSignature,
}
hash_enum!(MethodResolveError);

/// Wasm compilation error
#[derive(PartialEq, Eq, Clone, Debug, FromPyObject, From, EnumIntoPy)]
pub enum CompilationError {
    CodeDoesNotExist(CodeDoesNotExist),
    PrepareError(PrepareError),
    WasmerCompileError(WasmerCompileError),
    UnsupportedCompiler(UnsupportedCompiler),
}

impl From<CompilationError> for CompilationErrorOriginal {
    fn from(e: CompilationError) -> Self {
        type E = CompilationError;
        match e {
            E::CodeDoesNotExist(x) => Self::CodeDoesNotExist {
                account_id: x.account_id.into(),
            },
            E::PrepareError(x) => Self::PrepareError(x.into()),
            E::WasmerCompileError(x) => Self::WasmerCompileError { msg: x.msg },
            E::UnsupportedCompiler(x) => Self::UnsupportedCompiler { msg: x.msg },
        }
    }
}

impl From<CompilationErrorOriginal> for CompilationError {
    fn from(e: CompilationErrorOriginal) -> Self {
        type E = CompilationErrorOriginal;
        match e {
            E::CodeDoesNotExist { account_id } => Self::CodeDoesNotExist(CodeDoesNotExist {
                account_id: account_id.into(),
            }),
            E::PrepareError(x) => Self::PrepareError(x.into()),
            E::WasmerCompileError { msg } => Self::WasmerCompileError(WasmerCompileError { msg }),
            E::UnsupportedCompiler { msg } => {
                Self::UnsupportedCompiler(UnsupportedCompiler { msg })
            }
        }
    }
}

quick_struct_vm!(CodeDoesNotExist, "", account_id: AccountId);
quick_struct_vm_msg!(WasmerCompileError, "");
quick_struct_vm_msg!(UnsupportedCompiler, "");

#[pyclass(module = "pyonear.error.vm")]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[enum_original_mapping(PrepareErrorOriginal)]
/// Error that can occur while preparing or executing Wasm smart-contract.
pub enum PrepareError {
    /// Error happened while serializing the module.
    Serialization,
    /// Error happened while deserializing the module.
    Deserialization,
    /// Internal memory declaration has been found in the module.
    InternalMemoryDeclared,
    /// Gas instrumentation failed.
    ///
    /// This most likely indicates the module isn't valid.
    GasInstrumentation,
    /// Stack instrumentation failed.
    ///
    /// This  most likely indicates the module isn't valid.
    StackHeightInstrumentation,
    /// Error happened during instantiation.
    ///
    /// This might indicate that `start` function trapped, or module isn't
    /// instantiable and/or unlinkable.
    Instantiate,
    /// Error creating memory.
    Memory,
}
hash_enum!(PrepareError);

#[derive(PartialEq, Eq, Clone, Debug, FromPyObject, From, EnumIntoPy)]
pub enum HostError {
    Fieldless(HostErrorFieldless),
    GuestPanic(GuestPanic),
    InvalidPromiseIndex(InvalidPromiseIndex),
    InvalidPromiseResultIndex(InvalidPromiseResultIndex),
    InvalidRegisterId(InvalidRegisterId),
    IteratorWasInvalidated(IteratorWasInvalidated),
    InvalidReceiptIndex(InvalidReceiptIndex),
    InvalidIteratorIndex(InvalidIteratorIndex),
    ProhibitedInView(ProhibitedInView),
    NumberOfLogsExceeded(NumberOfLogsExceeded),
    KeyLengthExceeded(KeyLengthExceeded),
    ValueLengthExceeded(ValueLengthExceeded),
    TotalLogLengthExceeded(TotalLogLengthExceeded),
    NumberPromisesExceeded(NumberPromisesExceeded),
    NumberInputDataDependenciesExceeded(NumberInputDataDependenciesExceeded),
    ReturnedValueLengthExceeded(ReturnedValueLengthExceeded),
    ContractSizeExceeded(ContractSizeExceeded),
    Deprecated(Deprecated),
    ECRecoverError(ECRecoverError),
    Ed25519VerifyInvalidInput(Ed25519VerifyInvalidInput),
    AltBn128InvalidInput(AltBn128InvalidInput),
}

impl From<HostError> for HostErrorOriginal {
    fn from(h: HostError) -> Self {
        type H = HostError;
        match h {
            H::Fieldless(f) => match f {
                HostErrorFieldless::BadUTF16 => Self::BadUTF16,
                HostErrorFieldless::BadUTF8 => Self::BadUTF8,
                HostErrorFieldless::GasExceeded => Self::GasExceeded,
                HostErrorFieldless::GasLimitExceeded => Self::GasLimitExceeded,
                HostErrorFieldless::BalanceExceeded => Self::BalanceExceeded,
                HostErrorFieldless::EmptyMethodName => Self::EmptyMethodName,
                HostErrorFieldless::IntegerOverflow => Self::IntegerOverflow,
                HostErrorFieldless::CannotAppendActionToJointPromise => {
                    Self::CannotAppendActionToJointPromise
                }
                HostErrorFieldless::CannotReturnJointPromise => Self::CannotReturnJointPromise,
                HostErrorFieldless::MemoryAccessViolation => Self::MemoryAccessViolation,
                HostErrorFieldless::InvalidAccountId => Self::InvalidAccountId,
                HostErrorFieldless::InvalidMethodName => Self::InvalidMethodName,
                HostErrorFieldless::InvalidPublicKey => Self::InvalidPublicKey,
            },
            H::GuestPanic(x) => Self::GuestPanic {
                panic_msg: x.panic_msg,
            },
            H::InvalidPromiseIndex(x) => Self::InvalidPromiseIndex {
                promise_idx: x.promise_idx,
            },
            H::InvalidPromiseResultIndex(x) => Self::InvalidPromiseResultIndex {
                result_idx: x.result_idx,
            },
            H::InvalidRegisterId(x) => Self::InvalidRegisterId {
                register_id: x.register_id,
            },
            H::IteratorWasInvalidated(x) => Self::IteratorWasInvalidated {
                iterator_index: x.iterator_index,
            },
            H::InvalidReceiptIndex(x) => Self::InvalidReceiptIndex {
                receipt_index: x.receipt_index,
            },
            H::InvalidIteratorIndex(x) => Self::InvalidIteratorIndex {
                iterator_index: x.iterator_index,
            },
            H::ProhibitedInView(x) => Self::ProhibitedInView {
                method_name: x.method_name,
            },
            H::NumberOfLogsExceeded(x) => Self::NumberOfLogsExceeded { limit: x.limit },
            H::KeyLengthExceeded(x) => Self::KeyLengthExceeded {
                length: x.length,
                limit: x.limit,
            },
            H::ValueLengthExceeded(x) => Self::ValueLengthExceeded {
                length: x.length,
                limit: x.limit,
            },
            H::TotalLogLengthExceeded(x) => Self::TotalLogLengthExceeded {
                length: x.length,
                limit: x.limit,
            },
            H::NumberPromisesExceeded(x) => Self::NumberPromisesExceeded {
                number_of_promises: x.number_of_promises,
                limit: x.limit,
            },
            H::NumberInputDataDependenciesExceeded(x) => {
                Self::NumberInputDataDependenciesExceeded {
                    number_of_input_data_dependencies: x.number_of_input_data_dependencies,
                    limit: x.limit,
                }
            }
            H::ReturnedValueLengthExceeded(x) => Self::ReturnedValueLengthExceeded {
                length: x.length,
                limit: x.limit,
            },
            H::ContractSizeExceeded(x) => Self::ContractSizeExceeded {
                size: x.size,
                limit: x.limit,
            },
            H::Deprecated(x) => Self::Deprecated {
                method_name: x.method_name,
            },
            H::ECRecoverError(x) => Self::ECRecoverError { msg: x.msg },
            H::AltBn128InvalidInput(x) => Self::AltBn128InvalidInput { msg: x.msg },
            H::Ed25519VerifyInvalidInput(x) => Self::Ed25519VerifyInvalidInput { msg: x.msg },
        }
    }
}

impl From<HostErrorOriginal> for HostError {
    fn from(h: HostErrorOriginal) -> Self {
        type H = HostErrorOriginal;
        match h {
            H::BadUTF16 => Self::Fieldless(HostErrorFieldless::BadUTF16),
            H::BadUTF8 => Self::Fieldless(HostErrorFieldless::BadUTF8),
            H::GasExceeded => Self::Fieldless(HostErrorFieldless::GasExceeded),
            H::GasLimitExceeded => Self::Fieldless(HostErrorFieldless::GasLimitExceeded),
            H::BalanceExceeded => Self::Fieldless(HostErrorFieldless::BalanceExceeded),
            H::EmptyMethodName => Self::Fieldless(HostErrorFieldless::EmptyMethodName),
            H::IntegerOverflow => Self::Fieldless(HostErrorFieldless::IntegerOverflow),
            H::CannotAppendActionToJointPromise => {
                Self::Fieldless(HostErrorFieldless::CannotAppendActionToJointPromise)
            }
            H::CannotReturnJointPromise => {
                Self::Fieldless(HostErrorFieldless::CannotReturnJointPromise)
            }
            H::MemoryAccessViolation => Self::Fieldless(HostErrorFieldless::MemoryAccessViolation),
            H::InvalidAccountId => Self::Fieldless(HostErrorFieldless::InvalidAccountId),
            H::InvalidMethodName => Self::Fieldless(HostErrorFieldless::InvalidMethodName),
            H::InvalidPublicKey => Self::Fieldless(HostErrorFieldless::InvalidPublicKey),
            H::GuestPanic { panic_msg } => Self::GuestPanic(GuestPanic { panic_msg }),
            H::InvalidPromiseIndex { promise_idx } => {
                Self::InvalidPromiseIndex(InvalidPromiseIndex { promise_idx })
            }
            H::InvalidPromiseResultIndex { result_idx } => {
                Self::InvalidPromiseResultIndex(InvalidPromiseResultIndex { result_idx })
            }
            H::InvalidRegisterId { register_id } => {
                Self::InvalidRegisterId(InvalidRegisterId { register_id })
            }
            H::IteratorWasInvalidated { iterator_index } => {
                Self::IteratorWasInvalidated(IteratorWasInvalidated { iterator_index })
            }
            H::InvalidReceiptIndex { receipt_index } => {
                Self::InvalidReceiptIndex(InvalidReceiptIndex { receipt_index })
            }
            H::InvalidIteratorIndex { iterator_index } => {
                Self::InvalidIteratorIndex(InvalidIteratorIndex { iterator_index })
            }
            H::ProhibitedInView { method_name } => {
                Self::ProhibitedInView(ProhibitedInView { method_name })
            }
            H::NumberOfLogsExceeded { limit } => {
                Self::NumberOfLogsExceeded(NumberOfLogsExceeded { limit })
            }
            H::KeyLengthExceeded { length, limit } => {
                Self::KeyLengthExceeded(KeyLengthExceeded { length, limit })
            }
            H::ValueLengthExceeded { length, limit } => {
                Self::ValueLengthExceeded(ValueLengthExceeded { length, limit })
            }
            H::TotalLogLengthExceeded { length, limit } => {
                Self::TotalLogLengthExceeded(TotalLogLengthExceeded { length, limit })
            }
            H::NumberPromisesExceeded {
                number_of_promises,
                limit,
            } => Self::NumberPromisesExceeded(NumberPromisesExceeded {
                number_of_promises,
                limit,
            }),
            H::NumberInputDataDependenciesExceeded {
                number_of_input_data_dependencies,
                limit,
            } => Self::NumberInputDataDependenciesExceeded(NumberInputDataDependenciesExceeded {
                number_of_input_data_dependencies,
                limit,
            }),
            H::ReturnedValueLengthExceeded { length, limit } => {
                Self::ReturnedValueLengthExceeded(ReturnedValueLengthExceeded { length, limit })
            }
            H::ContractSizeExceeded { size, limit } => {
                Self::ContractSizeExceeded(ContractSizeExceeded { size, limit })
            }
            H::Deprecated { method_name } => Self::Deprecated(Deprecated { method_name }),
            H::ECRecoverError { msg } => Self::ECRecoverError(ECRecoverError { msg }),
            H::AltBn128InvalidInput { msg } => {
                Self::AltBn128InvalidInput(AltBn128InvalidInput { msg })
            }
            H::Ed25519VerifyInvalidInput { msg } => {
                Self::Ed25519VerifyInvalidInput(Ed25519VerifyInvalidInput { msg })
            }
        }
    }
}

#[pyclass(module = "pyonear.error.vm")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HostErrorFieldless {
    /// String encoding is bad UTF-16 sequence
    BadUTF16,
    /// String encoding is bad UTF-8 sequence
    BadUTF8,
    /// Exceeded the prepaid gas
    GasExceeded,
    /// Exceeded the maximum amount of gas allowed to burn per contract
    GasLimitExceeded,
    /// Exceeded the account balance
    BalanceExceeded,
    /// Tried to call an empty method name
    EmptyMethodName,
    /// IntegerOverflow happened during a contract execution
    IntegerOverflow,
    /// Actions can only be appended to non-joint promise.
    CannotAppendActionToJointPromise,
    /// Returning joint promise is currently prohibited
    CannotReturnJointPromise,
    /// Accessed memory outside the bounds
    MemoryAccessViolation,
    /// VM Logic returned an invalid account id
    InvalidAccountId,
    /// VM Logic returned an invalid method name
    InvalidMethodName,
    /// VM Logic provided an invalid public key
    InvalidPublicKey,
}
hash_enum!(HostErrorFieldless);

quick_struct_vm!(GuestPanic, "Smart contract panicked", panic_msg: String);
quick_struct_vm_u64!(
    InvalidPromiseIndex,
    "``promise_idx`` does not correspond to existing promises",
    promise_idx
);
quick_struct_vm_u64!(
    InvalidPromiseResultIndex,
    "Accessed invalid promise result index",
    result_idx
);
quick_struct_vm_u64!(
    InvalidRegisterId,
    "Accessed invalid register id",
    register_id
);
quick_struct_vm_u64!(IteratorWasInvalidated, "Iterator `iterator_index` was invalidated after its creation by performing a mutable operation on trie", iterator_index);
quick_struct_vm_u64!(
    InvalidReceiptIndex,
    "VM Logic returned an invalid receipt index",
    receipt_index
);
quick_struct_vm_u64!(
    InvalidIteratorIndex,
    "Iterator index ``iterator_index`` does not exist",
    iterator_index
);
quick_struct_vm_method_name!(
    ProhibitedInView,
    "``method_name`` is not allowed in view calls"
);
quick_struct_vm!(
    NumberOfLogsExceeded,
    "The total number of logs will exceed the limit.",
    limit: u64
);
quick_struct_vm_length_limit!(
    KeyLengthExceeded,
    "The storage key length exceeded the limit."
);
quick_struct_vm_length_limit!(
    ValueLengthExceeded,
    "The storage value length exceeded the limit."
);
quick_struct_vm_length_limit!(
    TotalLogLengthExceeded,
    "The total log length exceeded the limit."
);
quick_struct_vm!(
    NumberPromisesExceeded,
    "The maximum number of promises within a FunctionCall exceeded the limit.",
    number_of_promises: u64,
    limit: u64
);
quick_struct_vm!(
    NumberInputDataDependenciesExceeded,
    "The maximum number of input data dependencies exceeded the limit.",
    number_of_input_data_dependencies: u64,
    limit: u64
);
quick_struct_vm!(
    ReturnedValueLengthExceeded,
    "The returned value length exceeded the limit.",
    length: u64,
    limit: u64
);
quick_struct_vm_size_limit!(
    ContractSizeExceeded,
    "The contract size for DeployContract action exceeded the limit."
);
quick_struct_vm_method_name!(Deprecated, "The host function was deprecated.");
quick_struct_vm_msg!(ECRecoverError, "General errors for ECDSA recover.");
quick_struct_vm_msg!(
    Ed25519VerifyInvalidInput,
    "Invalid input to ed25519 signature verification function (e.g. signature cannot be derived from bytes)."
);
quick_struct_vm_msg!(
    AltBn128InvalidInput,
    "Invalid input to alt_bn128 familiy of functions (e.g., point which isn't on the curve)."
);

impl fmt::Display for PrepareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", PrepareErrorOriginal::from(*self))
    }
}

impl fmt::Display for WasmTrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", WasmTrapOriginal::from(*self))
    }
}

impl fmt::Display for MethodResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", MethodResolveErrorOriginal::from(*self))
    }
}

pub(crate) fn get_function_call_error_ser_members(py: Python) -> Vec<&PyType> {
    vec_type_object!(
        py,
        FunctionCallErrorSerFieldless,
        LinkError,
        WasmTrap,
        PyString
    )
}

pub(crate) fn create_vm_mod(py: Python<'_>) -> PyResult<&PyModule> {
    let m = PyModule::new(py, "vm")?;
    add_classes!(
        m,
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
        AltBn128InvalidInput
    );
    let host_error_members = vec_type_object!(
        py,
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
        AltBn128InvalidInput
    );
    add_union_to_module("HostError", m, py, host_error_members.clone())?;
    let compilation_error_members = vec_type_object!(
        py,
        CodeDoesNotExist,
        PrepareError,
        WasmerCompileError,
        UnsupportedCompiler
    );
    add_union_to_module("CompilationError", m, py, compilation_error_members.clone())?;
    add_classes!(
        m,
        CodeDoesNotExist,
        PrepareError,
        WasmerCompileError,
        UnsupportedCompiler
    );
    add_union!("CacheError", m, py, CacheErrorFieldless, SerializationError)?;
    add_classes!(m, CacheErrorFieldless, SerializationError);
    add_classes!(
        m,
        FunctionCallErrorSerFieldless,
        LinkError,
        MethodResolveError,
        WasmTrap
    );
    let mut function_call_error_ser_members = get_function_call_error_ser_members(py);
    function_call_error_ser_members.extend(compilation_error_members);
    function_call_error_ser_members.extend(host_error_members);
    add_union_to_module(
        "FunctionCallErrorSer",
        m,
        py,
        function_call_error_ser_members,
    )?;
    Ok(m)
}
