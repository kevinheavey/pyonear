use derive_more::{From, Into};
use near_crypto::Signer as SignerTrait;
use near_primitives::types::{Balance, Nonce};
use pyo3::{
    exceptions::PyValueError,
    prelude::*,
    types::{PyInt, PyTuple},
    PyTypeInfo,
};
use solders_macros::{common_methods, common_methods_core, richcmp_eq_only, EnumIntoPy};
use solders_traits::impl_display;
use std::fmt;
use std::hash::Hash;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use near_primitives::{
    serialize::{from_base64, to_base64},
    transaction::{
        verify_transaction_signature as verify_transaction_signature_original,
        Action as ActionOriginal, AddKeyAction as AddKeyActionOriginal,
        CreateAccountAction as CreateAccountActionOriginal,
        DeleteAccountAction as DeleteAccountActionOriginal,
        DeleteKeyAction as DeleteKeyActionOriginal,
        DeployContractAction as DeployContractActionOriginal,
        ExecutionMetadata as ExecutionMetadataOriginal,
        ExecutionOutcome as ExecutionOutcomeOriginal,
        ExecutionOutcomeWithId as ExecutionOutcomeWithIdOriginal,
        ExecutionOutcomeWithIdAndProof as ExecutionOutcomeWithIdAndProofOriginal,
        ExecutionStatus as ExecutionStatusOriginal,
        FunctionCallAction as FunctionCallActionOriginal,
        PartialExecutionStatus as PartialExecutionStatusOriginal,
        SignedTransaction as SignedTransactionOriginal, StakeAction as StakeActionOriginal,
        Transaction as TransactionOriginal, TransferAction as TransferActionOriginal,
    },
    types::Gas,
};
use near_primitives_core::profile::ProfileData as ProfileDataOriginal;

use crate::{
    account::AccessKey,
    account_id::AccountId,
    config::{ActionCosts, ExtCosts},
    crypto::{PublicKey, Signature, Signer},
    crypto_hash::CryptoHash,
    error::{core::get_tx_execution_error_members, exception::handle_py_value_err},
    merkle::MerklePathItem,
    vec_type_object,
};
use crate::{add_classes, add_union, error::core::TxExecutionError};
use crate::{hash_enum, quick_struct_boilerplate_core, quick_struct_boilerplate_core_no_json};

type LogEntry = String;

/// A ``Transaction`` is a collection of Actions that describe what should be done at the destination (the receiver account).
///
/// See https://docs.near.org/concepts/basics/transactions/overview for more.
///
/// Args:
///
///     signer_id (AccountId): The account on whose behalf the transaciton is signed.
///     public_key (PublicKey): A public key of the access key which was used to sign an account.
///     nonce (int): Used to determine order of transaction in the pool. It increments for a combination of `signer_id` and `public_key`,
///     receiver_id (AccountId): Receiver account for this transaction.
///     block_hash (CryptoHash): The hash of the block in the blockchain on top of which the given transaction is valid.
///     actions (list[Action]): A list of actions to be applied.
///
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
    Clone,
    From,
    Into,
)]
#[pyclass(module = "pyonear.transasction", subclass)]
pub struct Transaction(pub TransactionOriginal);

#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl Transaction {
    #[new]
    pub fn new(
        signer_id: AccountId,
        public_key: PublicKey,
        nonce: Nonce,
        receiver_id: AccountId,
        block_hash: CryptoHash,
        actions: Vec<Action>,
    ) -> Self {
        TransactionOriginal {
            signer_id: signer_id.into(),
            public_key: public_key.into(),
            nonce,
            receiver_id: receiver_id.into(),
            block_hash: block_hash.into(),
            actions: actions.into_iter().map(|x| x.into()).collect(),
        }
        .into()
    }

    /// AccountId: The account on whose behalf the transaction is signed.
    #[getter]
    pub fn signer_id(&self) -> AccountId {
        self.0.signer_id.clone().into()
    }
    /// PublicKey: A public key of the access key which was used to sign an account.
    /// Access key holds permissions for calling certain kinds of actions.
    #[getter]
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key.clone().into()
    }
    /// int: Nonce is used to determine order of transaction in the pool.
    /// It increments for a combination of `signer_id` and `public_key`
    #[getter]
    pub fn nonce(&self) -> Nonce {
        self.0.nonce
    }
    /// AccountId: Receiver account for this transaction
    #[getter]
    pub fn receiver_id(&self) -> AccountId {
        self.0.receiver_id.clone().into()
    }
    /// CryptoHash: The hash of the block in the blockchain on top of which the given transaction is valid
    #[getter]
    pub fn block_hash(&self) -> CryptoHash {
        self.0.block_hash.into()
    }
    /// list[Action]: A list of actions to be applied
    #[getter]
    pub fn actions(&self) -> Vec<Action> {
        self.0
            .actions
            .clone()
            .into_iter()
            .map(|x| x.into())
            .collect()
    }
    /// Computes a hash of the transaction for signing and size of serialized transaction
    pub fn get_hash_and_size(&self) -> (CryptoHash, u64) {
        let res = self.0.get_hash_and_size();
        (res.0.into(), res.1)
    }

    /// Sign this transaction.
    ///
    /// Args:
    ///     signer (Signer): The transasction signer.
    ///
    /// Returns:
    ///     SignedTransaction: The signed transaction.
    ///
    pub fn sign(&self, signer: Signer) -> SignedTransaction {
        let dyn_signer: Box<dyn SignerTrait> = match signer {
            Signer::Empty(x) => Box::new(x.0),
            Signer::InMemory(x) => Box::new(x.0),
        };
        self.0.clone().sign(&*dyn_signer).into()
    }

    /// Mutably add a ``CreateAccount`` action to this transaction.
    ///
    /// Returns:
    ///     Transaction: the transaction object.
    ///
    pub fn create_account(&mut self) -> Self {
        self.0.clone().create_account().into()
    }

    /// Mutably add a ``DeployContract`` action to this transaction.
    ///
    /// Args:
    ///     code (bytes | Sequence[int]): The webassembly binary.
    ///
    /// Returns:
    ///     Transaction: the transaction object.
    ///
    pub fn deploy_contract(&mut self, code: Vec<u8>) -> Self {
        self.0.clone().deploy_contract(code).into()
    }

    /// Mutably add a ``FunctionCall`` action to this transaction.
    ///
    /// Args:
    ///     method_name (str): The name of the method to call.
    ///     args (bytes | Sequence[int]): The arguments.
    ///     gas (int): Max amount of gas that method call can use.
    ///     deposit (int): Amount of NEAR (in yoctoNEAR) to send together with the call.
    ///
    /// Returns:
    ///     Transaction: the transaction object.
    ///
    pub fn function_call(
        &mut self,
        method_name: String,
        args: Vec<u8>,
        gas: Gas,
        deposit: Balance,
    ) -> Self {
        self.0
            .clone()
            .function_call(method_name, args, gas, deposit)
            .into()
    }

    /// Mutably add a ``Transfer`` action to this transaction.
    ///
    /// Args:
    ///     deposit (int): Amount of NEAR (in yoctoNEAR) to send.
    ///
    /// Returns:
    ///     Transaction: the transaction object.
    ///
    pub fn transfer(&mut self, deposit: Balance) -> Self {
        self.0.clone().transfer(deposit).into()
    }

    /// Mutably add a ``Stake`` action to this transaction.
    ///
    /// Args:
    ///     stake (int): Amount of tokens to stake.
    ///     public_key (PublicKey): Validator key which will be used to sign transactions on behalf of signer_id.
    ///
    /// Returns:
    ///     Transaction: the transaction object.
    ///
    pub fn stake(&mut self, stake: Balance, public_key: PublicKey) -> Self {
        self.0.clone().stake(stake, public_key.into()).into()
    }

    /// Mutably add an ``AddKey`` action to this transaction.
    ///
    /// Args:
    ///     public_key (PublicKey): A public key which will be associated with an access_key.
    ///     access_key (AccessKey): An access key with the permission.
    ///
    /// Returns:
    ///     Transaction: the transaction object.
    ///
    pub fn add_key(&mut self, public_key: PublicKey, access_key: AccessKey) -> Self {
        self.0
            .clone()
            .add_key(public_key.into(), access_key.into())
            .into()
    }

    /// Mutably add a ``DeleteKey`` action to this transaction.
    ///
    /// Args:
    ///     public_key (PublicKey): A public key associated with the access_key to be deleted.
    ///
    /// Returns:
    ///     Transaction: the transaction object.
    ///
    pub fn delete_key(&mut self, public_key: PublicKey) -> Self {
        self.0.clone().delete_key(public_key.into()).into()
    }

    /// Mutably add a ``DeleteAccount`` action to this transaction.
    ///
    /// Args:
    ///     benficiary_id (AccountId)
    ///
    /// Returns:
    ///     Transaction: the transaction object.
    ///
    pub fn delete_account(&mut self, beneficiary_id: AccountId) -> Self {
        self.0.clone().delete_account(beneficiary_id.into()).into()
    }
}
impl_display!(Transaction);
quick_struct_boilerplate_core!(Transaction);

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
    Clone,
    FromPyObject,
    From,
    EnumIntoPy,
)]
pub enum Action {
    CreateAccount(CreateAccountAction),
    DeployContract(DeployContractAction),
    FunctionCall(FunctionCallAction),
    Transfer(TransferAction),
    Stake(StakeAction),
    AddKey(AddKeyAction),
    DeleteKey(DeleteKeyAction),
    DeleteAccount(DeleteAccountAction),
}

impl From<ActionOriginal> for Action {
    fn from(a: ActionOriginal) -> Self {
        match a {
            ActionOriginal::CreateAccount(x) => Self::CreateAccount(x.into()),
            ActionOriginal::DeployContract(x) => Self::DeployContract(x.into()),
            ActionOriginal::FunctionCall(x) => Self::FunctionCall(x.into()),
            ActionOriginal::Transfer(x) => Self::Transfer(x.into()),
            ActionOriginal::Stake(x) => Self::Stake(x.into()),
            ActionOriginal::AddKey(x) => Self::AddKey(x.into()),
            ActionOriginal::DeleteKey(x) => Self::DeleteKey(x.into()),
            ActionOriginal::DeleteAccount(x) => Self::DeleteAccount(x.into()),
        }
    }
}

impl From<Action> for ActionOriginal {
    fn from(a: Action) -> Self {
        match a {
            Action::CreateAccount(x) => Self::CreateAccount(x.into()),
            Action::DeployContract(x) => Self::DeployContract(x.into()),
            Action::FunctionCall(x) => Self::FunctionCall(x.into()),
            Action::Transfer(x) => Self::Transfer(x.into()),
            Action::Stake(x) => Self::Stake(x.into()),
            Action::AddKey(x) => Self::AddKey(x.into()),
            Action::DeleteKey(x) => Self::DeleteKey(x.into()),
            Action::DeleteAccount(x) => Self::DeleteAccount(x.into()),
        }
    }
}

macro_rules! action_struct {
    ($name:ident, $inner:ty, $doc:literal) => {
        #[doc=$doc]
        #[derive(
            BorshSerialize,
            BorshDeserialize,
            Serialize,
            Deserialize,
            PartialEq,
            Eq,
            Clone,
            Debug,
            From,
            Into,
        )]
        #[pyclass(module = "pyonear.transasction", subclass)]
        pub struct $name(pub $inner);
        impl_display!($name);
        quick_struct_boilerplate_core!($name);
    };
}

action_struct!(
    CreateAccountAction,
    CreateAccountActionOriginal,
    "Create account action"
);

#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl CreateAccountAction {
    #[new]
    fn new() -> Self {
        CreateAccountActionOriginal {}.into()
    }
}

action_struct!(
    DeployContractAction,
    DeployContractActionOriginal,
    "Deploy contract action"
);

#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl DeployContractAction {
    #[new]
    fn new(code: Vec<u8>) -> Self {
        DeployContractActionOriginal { code }.into()
    }

    /// list[int]: WebAssembly binary
    #[getter]
    pub fn code(&self) -> Vec<u8> {
        self.0.code.clone()
    }
}

action_struct!(FunctionCallAction, FunctionCallActionOriginal, "");

#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl FunctionCallAction {
    #[new]
    fn new(method_name: String, args: Vec<u8>, gas: Gas, deposit: Balance) -> Self {
        FunctionCallActionOriginal {
            method_name,
            args,
            gas,
            deposit,
        }
        .into()
    }

    /// str: The name of the method to call
    #[getter]
    pub fn method_name(&self) -> String {
        self.0.method_name.clone()
    }
    /// list[int]: Arguments to pass to method.
    #[getter]
    pub fn args(&self) -> Vec<u8> {
        self.0.args.clone()
    }
    /// int: Max amount of gas that method call can use.
    #[getter]
    pub fn gas(&self) -> Gas {
        self.0.gas
    }
    /// int: Amount of NEAR (in yoctoNEAR) to send together with the call.
    #[getter]
    pub fn deposit(&self) -> Balance {
        self.0.deposit
    }
}

action_struct!(TransferAction, TransferActionOriginal, "");

#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl TransferAction {
    #[new]
    pub fn new(deposit: Balance) -> Self {
        TransferActionOriginal { deposit }.into()
    }

    /// int: The amount to transfer, in yoctoNEAR.
    #[getter]
    pub fn deposit(&self) -> Balance {
        self.0.deposit
    }
}

action_struct!(
    StakeAction,
    StakeActionOriginal,
    "An action which stakes signer_id tokens and sets up validator public key"
);

#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl StakeAction {
    #[new]
    pub fn new(stake: Balance, public_key: PublicKey) -> Self {
        StakeActionOriginal {
            stake,
            public_key: public_key.into(),
        }
        .into()
    }

    /// int: Amount of tokens to stake.
    #[getter]
    pub fn stake(&self) -> Balance {
        self.0.stake
    }

    /// PublicKey: Validator key which will be used to sign transactions on behalf of signer_id.
    #[getter]
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key.clone().into()
    }
}

action_struct!(AddKeyAction, AddKeyActionOriginal, "");

#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl AddKeyAction {
    #[new]
    pub fn new(public_key: PublicKey, access_key: AccessKey) -> Self {
        AddKeyActionOriginal {
            public_key: public_key.into(),
            access_key: access_key.into(),
        }
        .into()
    }

    /// PublicKey: A public key which will be associated with an access_key.
    #[getter]
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key.clone().into()
    }

    /// AccessKey: An access key with the permission.
    #[getter]
    pub fn access_key(&self) -> AccessKey {
        self.0.access_key.clone().into()
    }
}

action_struct!(DeleteKeyAction, DeleteKeyActionOriginal, "");

#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl DeleteKeyAction {
    #[new]
    pub fn new(public_key: PublicKey) -> Self {
        DeleteKeyActionOriginal {
            public_key: public_key.into(),
        }
        .into()
    }

    /// PublicKey: A public key associated with the access_key to be deleted.
    #[getter]
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key.clone().into()
    }
}

action_struct!(DeleteAccountAction, DeleteAccountActionOriginal, "");

#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl DeleteAccountAction {
    #[new]
    pub fn new(beneficiary_id: AccountId) -> Self {
        DeleteAccountActionOriginal {
            beneficiary_id: beneficiary_id.into(),
        }
        .into()
    }

    /// AccountId: the ID of the account to be deleted.
    #[getter]
    pub fn beneficiary_id(&self) -> AccountId {
        self.0.beneficiary_id.clone().into()
    }
}

/// A ``SignedTransction`` is the result of calling ``Transaction.sign``.
/// The data inside a ``SignedTransaction`` cannot be changed.
/// If you have a ``SignedTransction`` and you want to make some changes,
/// use ``my_signed_tx.transaction`` to retrieve an unsigned transaction object.
///
/// Args:
///     signature (Signature): The transaction signature.
///     transaction (Transaction): The unsigned transaction.
///
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
    Clone,
    From,
    Into,
    Hash,
)]
#[pyclass(module = "pyonear.transasction", subclass)]
pub struct SignedTransaction(pub SignedTransactionOriginal);
impl_display!(SignedTransaction);
quick_struct_boilerplate_core!(SignedTransaction);

impl AsRef<SignedTransactionOriginal> for SignedTransaction {
    fn as_ref(&self) -> &SignedTransactionOriginal {
        &self.0
    }
}

#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl SignedTransaction {
    #[new]
    pub fn new(signature: Signature, transaction: Transaction) -> Self {
        SignedTransactionOriginal::new(signature.into(), transaction.into()).into()
    }

    /// Signature: The transaction signature.
    #[getter]
    pub fn signature(&self) -> Signature {
        self.0.signature.clone().into()
    }

    /// Transaction: The unsigned transaction.
    #[getter]
    pub fn transaction(&self) -> Transaction {
        self.0.transaction.clone().into()
    }

    /// CryptoHash: The hash of the transaction.
    #[getter]
    pub fn hash(&self) -> CryptoHash {
        self.0.get_hash().into()
    }

    /// int: The size of the serialized transaction in bytes.
    #[getter]
    pub fn size(&self) -> u64 {
        self.0.get_size()
    }

    /// Convert to a base64 string.
    ///
    /// Returns:
    ///     str
    pub fn to_base64(&self) -> String {
        to_base64(self.0.try_to_vec().unwrap())
    }

    #[staticmethod]
    /// Build to a base64 string.
    ///
    /// Args:
    ///     s (str): The base64-encoded transaction.
    ///
    /// Returns:
    ///     SignedTransaction
    ///
    pub fn from_base64(s: &str) -> PyResult<Self> {
        let bytes = from_base64(s).map_err(|e| PyValueError::new_err(e.to_string()))?;
        handle_py_value_err(SignedTransactionOriginal::try_from_slice(&bytes))
    }
}

#[pyclass(module = "pyonear.transaction")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExecutionStatusFieldless {
    /// The execution is pending or unknown.
    Unknown,
}
hash_enum!(ExecutionStatusFieldless);

/// The status of execution for a transaction or a receipt.
#[derive(PartialEq, Clone, Eq, FromPyObject, EnumIntoPy)]
pub enum ExecutionStatus {
    Fieldless(ExecutionStatusFieldless),
    Failure(TxExecutionError),
    SuccessValue(Vec<u8>),
    SuccessReceiptId(CryptoHash),
}

impl From<ExecutionStatus> for ExecutionStatusOriginal {
    fn from(e: ExecutionStatus) -> Self {
        match e {
            ExecutionStatus::Fieldless(f) => match f {
                ExecutionStatusFieldless::Unknown => Self::Unknown,
            },
            ExecutionStatus::Failure(x) => Self::Failure(x.into()),
            ExecutionStatus::SuccessValue(x) => Self::SuccessValue(x),
            ExecutionStatus::SuccessReceiptId(x) => Self::SuccessReceiptId(x.into()),
        }
    }
}

impl From<ExecutionStatusOriginal> for ExecutionStatus {
    fn from(e: ExecutionStatusOriginal) -> Self {
        match e {
            ExecutionStatusOriginal::Unknown => Self::Fieldless(ExecutionStatusFieldless::Unknown),
            ExecutionStatusOriginal::Failure(x) => Self::Failure(x.into()),
            ExecutionStatusOriginal::SuccessValue(x) => Self::SuccessValue(x),
            ExecutionStatusOriginal::SuccessReceiptId(x) => Self::SuccessReceiptId(x.into()),
        }
    }
}

#[pyclass(module = "pyonear.transaction")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PartialExecutionStatusFieldless {
    Unknown,
    Failure,
}
hash_enum!(PartialExecutionStatusFieldless);

/// ExecutionStatus for proof. Excludes failure debug info.
#[derive(PartialEq, Eq, Clone, FromPyObject, EnumIntoPy)]
pub enum PartialExecutionStatus {
    Fieldless(PartialExecutionStatusFieldless),
    SuccessValue(Vec<u8>),
    SuccessReceiptId(CryptoHash),
}

impl From<PartialExecutionStatus> for PartialExecutionStatusOriginal {
    fn from(e: PartialExecutionStatus) -> Self {
        type E = PartialExecutionStatus;
        match e {
            E::Fieldless(x) => match x {
                PartialExecutionStatusFieldless::Failure => Self::Failure,
                PartialExecutionStatusFieldless::Unknown => Self::Unknown,
            },
            E::SuccessValue(x) => Self::SuccessValue(x),
            E::SuccessReceiptId(x) => Self::SuccessReceiptId(x.into()),
        }
    }
}

impl From<PartialExecutionStatusOriginal> for PartialExecutionStatus {
    fn from(e: PartialExecutionStatusOriginal) -> Self {
        type E = PartialExecutionStatusOriginal;
        match e {
            E::Failure => Self::Fieldless(PartialExecutionStatusFieldless::Failure),
            E::Unknown => Self::Fieldless(PartialExecutionStatusFieldless::Unknown),
            E::SuccessValue(x) => Self::SuccessValue(x),
            E::SuccessReceiptId(x) => Self::SuccessReceiptId(x.into()),
        }
    }
}

/// Execution outcome for one signed transaction or one receipt.
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Debug, Clone, From, Into)]
#[pyclass(module = "pyonear.transasction", subclass)]
pub struct ExecutionOutcome(pub ExecutionOutcomeOriginal);
#[richcmp_eq_only]
#[common_methods_core]
#[pymethods]
impl ExecutionOutcome {
    #[new]
    pub fn new(
        logs: Vec<LogEntry>,
        receipt_ids: Vec<CryptoHash>,
        gas_burnt: Gas,
        tokens_burnt: Balance,
        executor_id: AccountId,
        status: ExecutionStatus,
        metadata: ExecutionMetadata,
    ) -> Self {
        ExecutionOutcomeOriginal {
            logs,
            receipt_ids: receipt_ids.into_iter().map(|x| x.into()).collect(),
            gas_burnt,
            tokens_burnt,
            executor_id: executor_id.into(),
            status: status.into(),
            metadata: metadata.into(),
        }
        .into()
    }
    /// list[str]: Logs from this transaction or receipt.
    #[getter]
    pub fn logs(&self) -> Vec<LogEntry> {
        self.0.logs.clone()
    }
    /// list[CryptoHash]: Receipt IDs generated by this transaction or receipt.
    #[getter]
    pub fn receipt_ids(&self) -> Vec<CryptoHash> {
        self.0
            .receipt_ids
            .clone()
            .into_iter()
            .map(|x| x.into())
            .collect()
    }
    /// int: The amount of the gas burnt by the given transaction or receipt.
    #[getter]
    pub fn gas_burnt(&self) -> Gas {
        self.0.gas_burnt
    }
    /// int: The amount of tokens burnt corresponding to the burnt gas amount.
    /// This value doesn't always equal to the ``gas_burnt`` multiplied by the gas price, because
    /// the prepaid gas price might be lower than the actual gas price and it creates a deficit.
    #[getter]
    pub fn tokens_burnt(&self) -> Balance {
        self.0.tokens_burnt
    }
    /// AccountId: The id of the account on which the execution happens. For transaction this is signer_id,
    /// for receipt this is receiver_id.
    #[getter]
    pub fn executor_id(&self) -> AccountId {
        self.0.executor_id.clone().into()
    }
    /// ExecutionStatus: Execution status. Contains the result in case of successful execution.
    /// NOTE: Should be the latest field since it contains unparsable by light client
    /// ExecutionStatus::Failure
    #[getter]
    pub fn status(&self) -> ExecutionStatus {
        self.0.status.clone().into()
    }
    /// ExecutionMetadata: Execution metadata, versioned
    #[getter]
    pub fn metadata(&self) -> ExecutionMetadata {
        self.0.metadata.clone().into()
    }
}
impl_display!(ExecutionOutcome);
quick_struct_boilerplate_core_no_json!(ExecutionOutcome);

#[pyclass(module = "pyonear.transaction")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExecutionMetadataFieldless {
    /// V1: Empty Metadata
    V1,
}
hash_enum!(ExecutionMetadataFieldless);

/// Profile of gas consumption.
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Debug, Clone, Default, From, Into)]
#[pyclass(module = "pyonear.transasction", subclass)]
pub struct ProfileData(pub ProfileDataOriginal);

#[richcmp_eq_only]
#[common_methods_core]
#[pymethods]
impl ProfileData {
    #[new]
    pub fn new() -> Self {
        ProfileDataOriginal::new().into()
    }

    /// Args:
    ///     other (ProfileData)
    ///
    /// Returns:
    ///     None
    pub fn merge(&mut self, other: &ProfileData) {
        self.0.merge(&other.0)
    }

    /// Args:
    ///     action (ActionCosts)
    ///     value (int)
    ///
    /// Returns:
    ///     None
    pub fn add_action_cost(&mut self, action: ActionCosts, value: u64) {
        self.0.add_action_cost(action.into(), value)
    }

    /// Args:
    ///     ext (ExtCosts)
    ///     value (int)
    ///
    /// Returns:
    ///     None
    pub fn add_ext_cost(&mut self, ext: ExtCosts, value: u64) {
        self.0.add_ext_cost(ext.into(), value)
    }

    /// WasmInstruction is the only cost we don't explicitly account for.
    /// Instead, we compute it at the end of contract call as the difference
    /// between total gas burnt and what we've explicitly accounted for in the
    /// profile.
    ///
    /// This is because WasmInstruction is the hottest cost and is implemented
    /// with the help on the VM side, so we don't want to have profiling logic
    /// there both for simplicity and efficiency reasons.
    ///
    /// Args:
    ///     total_gas_burnt (Sequence[bytes]): The total gas burnt by the contract call.
    ///     program_id (Pubkey): The program ID.
    ///
    /// Returns:
    ///     int: the WASM instruction cost.
    ///
    pub fn compute_wasm_instruction_cost(&mut self, total_gas_burnt: u64) {
        self.0.compute_wasm_instruction_cost(total_gas_burnt)
    }

    /// See https://docs.rs/near-primitives-core/latest/near_primitives_core/profile/struct.ProfileData.html#method.get_action_cost
    ///
    /// Args:
    ///     action (ActionCosts)
    ///
    /// Returns:
    ///     int
    ///
    pub fn get_action_cost(&self, action: ActionCosts) -> u64 {
        self.0.get_action_cost(action.into())
    }

    /// See https://docs.rs/near-primitives-core/latest/near_primitives_core/profile/struct.ProfileData.html#method.get_ext_cost
    ///
    /// Args:
    ///     ext (ExtCosts)
    ///
    /// Returns:
    ///     int
    pub fn get_ext_cost(&self, ext: ExtCosts) -> u64 {
        self.0.get_ext_cost(ext.into())
    }

    /// See https://docs.rs/near-primitives-core/latest/near_primitives_core/profile/struct.ProfileData.html#method.host_gas
    ///
    /// Returns:
    ///     int
    pub fn host_gas(&self) -> u64 {
        self.0.host_gas()
    }

    /// See https://docs.rs/near-primitives-core/latest/near_primitives_core/profile/struct.ProfileData.html#method.action_gas
    ///
    /// Returns:
    ///     int
    pub fn action_gas(&self) -> u64 {
        self.0.action_gas()
    }
}

impl std::fmt::Display for ProfileData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
quick_struct_boilerplate_core_no_json!(ProfileData);

#[derive(PartialEq, Clone, Eq, Debug, FromPyObject, EnumIntoPy)]
pub enum ExecutionMetadata {
    Fieldless(ExecutionMetadataFieldless),
    V2(ProfileData),
}

impl From<ExecutionMetadata> for ExecutionMetadataOriginal {
    fn from(m: ExecutionMetadata) -> Self {
        type M = ExecutionMetadata;
        match m {
            M::Fieldless(f) => match f {
                ExecutionMetadataFieldless::V1 => Self::V1,
            },
            M::V2(x) => Self::V2(x.into()),
        }
    }
}

impl From<ExecutionMetadataOriginal> for ExecutionMetadata {
    fn from(m: ExecutionMetadataOriginal) -> Self {
        type M = ExecutionMetadataOriginal;
        match m {
            M::V1 => Self::Fieldless(ExecutionMetadataFieldless::V1),
            M::V2(x) => Self::V2(x.into()),
        }
    }
}

/// Execution outcome with the identifier.
/// For a signed transaction, the ID is the hash of the transaction.
/// For a receipt, the ID is the receipt ID.
#[derive(PartialEq, Clone, Debug, BorshSerialize, BorshDeserialize, Eq, From, Into)]
#[pyclass(module = "pyonear.transasction", subclass)]
pub struct ExecutionOutcomeWithId(pub ExecutionOutcomeWithIdOriginal);

#[richcmp_eq_only]
#[common_methods_core]
#[pymethods]
impl ExecutionOutcomeWithId {
    #[new]
    pub fn new(id: CryptoHash, outcome: ExecutionOutcome) -> Self {
        ExecutionOutcomeWithIdOriginal {
            id: id.into(),
            outcome: outcome.into(),
        }
        .into()
    }
    /// CryptoHash: The transaction hash or the receipt ID.
    #[getter]
    pub fn id(&self) -> CryptoHash {
        self.0.id.into()
    }
    /// ExecutionOutcome: Should be the latest field since contains unparsable by light client ExecutionStatus::Failure
    #[getter]
    pub fn outcome(&self) -> ExecutionOutcome {
        self.0.outcome.clone().into()
    }

    /// Returns:
    ///     list[CryptoHash]
    pub fn to_hashes(&self) -> Vec<CryptoHash> {
        self.0.to_hashes().into_iter().map(|x| x.into()).collect()
    }
}
impl_display!(ExecutionOutcomeWithId);
quick_struct_boilerplate_core_no_json!(ExecutionOutcomeWithId);

/// Execution outcome with path from it to the outcome root and ID.
#[derive(PartialEq, Clone, Default, Debug, BorshSerialize, BorshDeserialize, Eq, From, Into)]
#[pyclass(module = "pyonear.transasction", subclass)]
pub struct ExecutionOutcomeWithIdAndProof(pub ExecutionOutcomeWithIdAndProofOriginal);

#[richcmp_eq_only]
#[common_methods_core]
#[pymethods]
impl ExecutionOutcomeWithIdAndProof {
    #[new]
    pub fn new(
        proof: Vec<MerklePathItem>,
        block_hash: CryptoHash,
        outcome_with_id: ExecutionOutcomeWithId,
    ) -> Self {
        ExecutionOutcomeWithIdAndProofOriginal {
            proof: proof.into_iter().map(|x| x.into()).collect(),
            block_hash: block_hash.into(),
            outcome_with_id: outcome_with_id.into(),
        }
        .into()
    }

    /// list[MerklePathItem]: Path from the execution outcome to the outcome root.
    #[getter]
    pub fn proof(&self) -> Vec<MerklePathItem> {
        self.0.proof.clone().into_iter().map(|x| x.into()).collect()
    }
    /// CryptoHash: The block hash.
    #[getter]
    pub fn block_hash(&self) -> CryptoHash {
        self.0.block_hash.into()
    }
    /// ExecutionOutcomeWithId: Should be the latest field since contains unparsable by light client ExecutionStatus::Failure
    #[getter]
    pub fn outcome_with_id(&self) -> ExecutionOutcomeWithId {
        self.0.outcome_with_id.clone().into()
    }

    /// Get the outcome ID.
    ///
    /// Returns:
    ///     CryptoHash: outcome ID.
    ///
    pub fn id(&self) -> CryptoHash {
        let underlying = *self.0.id();
        underlying.into()
    }
}
impl_display!(ExecutionOutcomeWithIdAndProof);
quick_struct_boilerplate_core_no_json!(ExecutionOutcomeWithIdAndProof);

#[pyfunction]
pub fn verify_transaction_signature(
    transaction: &SignedTransaction,
    public_keys: Vec<PublicKey>,
) -> bool {
    verify_transaction_signature_original(
        transaction.as_ref(),
        &public_keys.iter().map(|x| x.into()).collect::<Vec<_>>(),
    )
}

pub(crate) fn create_transaction_mod(py: Python<'_>) -> PyResult<&PyModule> {
    let m = PyModule::new(py, "transaction")?;
    add_classes!(
        m,
        CreateAccountAction,
        DeployContractAction,
        FunctionCallAction,
        TransferAction,
        StakeAction,
        AddKeyAction,
        DeleteKeyAction,
        DeleteAccountAction
    );
    add_union!(
        "Action",
        m,
        py,
        CreateAccountAction,
        DeployContractAction,
        FunctionCallAction,
        TransferAction,
        StakeAction,
        AddKeyAction,
        DeleteKeyAction,
        DeleteAccountAction
    )?;
    m.add_function(wrap_pyfunction!(verify_transaction_signature, m)?)?;
    let typing = py.import("typing")?;
    let union = typing.getattr("Union")?;
    let list_type = typing.getattr("List")?;
    let list_int = list_type.get_item(PyInt::type_object(py))?;
    add_classes!(m, ExecutionStatusFieldless);
    let execution_status_members_py_type =
        vec_type_object!(py, ExecutionStatusFieldless, CryptoHash);
    let mut execution_status_members = execution_status_members_py_type
        .iter()
        .map(|x| x.as_ref())
        .collect::<Vec<_>>();
    let tx_execution_error_members = get_tx_execution_error_members(py);

    execution_status_members.extend(
        tx_execution_error_members
            .iter()
            .map(|x| x.as_ref())
            .collect::<Vec<_>>(),
    );
    execution_status_members.push(list_int);
    m.add(
        "ExecutionStatus",
        union.get_item(PyTuple::new(py, execution_status_members))?,
    )?;
    m.add_class::<PartialExecutionStatusFieldless>()?;

    m.add(
        "PartialExecutionStatus",
        union.get_item(PyTuple::new(
            py,
            vec![
                PartialExecutionStatusFieldless::type_object(py).as_ref(),
                CryptoHash::type_object(py).as_ref(),
                list_int,
            ],
        ))?,
    )?;
    add_classes!(m, ExecutionMetadataFieldless, ProfileData);
    add_union!(
        "ExecutionMetadata",
        m,
        py,
        ExecutionMetadataFieldless,
        ProfileData
    )?;
    add_classes!(
        m,
        Transaction,
        SignedTransaction,
        ExecutionOutcome,
        ExecutionOutcomeWithId,
        ExecutionOutcomeWithIdAndProof
    );
    Ok(m)
}
