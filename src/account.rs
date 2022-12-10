use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{From, Into};
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use solders_macros::{common_methods, pyhash, richcmp_eq_only, EnumIntoPy};
use solders_traits::{common_methods_default, PyHash, RichcmpEqualityOnly};

use near_primitives::{
    account::{
        AccessKey as AccessKeyOriginal, AccessKeyPermission as AccessKeyPermissionOriginal,
        Account as AccountOriginal, AccountVersion as AccountVersionOriginal,
        FunctionCallPermission as FunctionCallPermissionOriginal,
    },
    types::{Balance, Nonce, StorageUsage},
};

use crate::{
    add_classes, add_union, crypto_hash::CryptoHash, py_from_bytes_general_via_borsh,
    pybytes_general_via_borsh,
};

#[pyclass(module = "pyonear.account")]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
    Clone,
    Copy,
    Hash,
)]
pub enum AccountVersion {
    V1,
}

impl PyHash for AccountVersion {}

#[pyhash]
#[pymethods]
impl AccountVersion {}

impl Default for AccountVersion {
    fn default() -> Self {
        AccountVersionOriginal::default().into()
    }
}

impl From<AccountVersionOriginal> for AccountVersion {
    fn from(v: AccountVersionOriginal) -> Self {
        match v {
            AccountVersionOriginal::V1 => Self::V1,
        }
    }
}

impl From<AccountVersion> for AccountVersionOriginal {
    fn from(v: AccountVersion) -> Self {
        match v {
            AccountVersion::V1 => Self::V1,
        }
    }
}

/// Per account information stored in the state.
#[pyclass(module = "pyonear.account", subclass)]
#[derive(
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
    Clone,
    From,
    Into,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct Account(pub AccountOriginal);

#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl Account {
    /// Max number of bytes an account can have in its state (excluding contract code)
    /// before it is infeasible to delete.
    #[classattr]
    pub const MAX_ACCOUNT_DELETION_STORAGE_USAGE: u64 =
        AccountOriginal::MAX_ACCOUNT_DELETION_STORAGE_USAGE;

    #[new]
    pub fn new(
        amount: Balance,
        locked: Balance,
        code_hash: CryptoHash,
        storage_usage: StorageUsage,
    ) -> Self {
        AccountOriginal::new(amount, locked, code_hash.into(), storage_usage).into()
    }

    /// int: The total not locked tokens.
    #[getter]
    pub fn amount(&self) -> Balance {
        self.0.amount()
    }

    /// int: The amount locked due to staking.
    #[getter]
    pub fn locked(&self) -> Balance {
        self.0.locked()
    }

    /// CryptoHash: Hash of the code stored in the storage for this account.
    #[getter]
    pub fn code_hash(&self) -> CryptoHash {
        self.0.code_hash().into()
    }

    /// int: Storage used by the given account, includes account id, this struct, access keys and other data.
    #[getter]
    pub fn storage_usage(&self) -> StorageUsage {
        self.0.storage_usage()
    }

    /// AccountVersion: Version of Account in re migrations and similar
    #[getter]
    pub fn version(&self) -> AccountVersion {
        self.0.version().into()
    }

    #[setter]
    pub fn set_amount(&mut self, amount: Balance) {
        self.0.set_amount(amount);
    }

    #[setter]
    pub fn set_locked(&mut self, locked: Balance) {
        self.0.set_locked(locked);
    }

    #[setter]
    pub fn set_code_hash(&mut self, code_hash: CryptoHash) {
        self.0.set_code_hash(code_hash.into());
    }

    #[setter]
    pub fn set_storage_usage(&mut self, storage_usage: StorageUsage) {
        self.0.set_storage_usage(storage_usage);
    }

    #[setter]
    pub fn set_version(&mut self, version: AccountVersion) {
        self.0.set_version(version.into());
    }
}

impl RichcmpEqualityOnly for Account {}
py_from_bytes_general_via_borsh!(Account);
pybytes_general_via_borsh!(Account);
impl Display for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
common_methods_default!(Account);

/// Access key provides limited access to an account. Each access key belongs to some account and
/// is identified by a unique (within the account) public key. One account may have large number of
/// access keys. Access keys allow to act on behalf of the account by restricting transactions
/// that can be issued.
#[pyclass(module = "pyonear.account", subclass)]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Debug,
    From,
    Into,
)]
pub struct AccessKey(pub AccessKeyOriginal);

impl PyHash for AccessKey {}

#[richcmp_eq_only]
#[common_methods]
#[pyhash]
#[pymethods]
impl AccessKey {
    #[new]
    pub fn new(nonce: Nonce, permission: AccessKeyPermission) -> Self {
        AccessKeyOriginal {
            nonce,
            permission: permission.into(),
        }
        .into()
    }

    /// int: Nonce for this access key, used for tx nonce generation. When access key is created, nonce
    /// is set to ``(block_height - 1) * 1e6`` to avoid tx hash collision on access key re-creation.
    /// See <https://github.com/near/nearcore/issues/3779> for more details.
    #[getter]
    pub fn nonce(&self) -> Nonce {
        self.0.nonce
    }

    /// AccessKeyPermission: Defines permissions for this access key.
    #[getter]
    pub fn permission(&self) -> AccessKeyPermission {
        self.0.permission.clone().into()
    }
    #[classattr]
    pub const ACCESS_KEY_NONCE_RANGE_MULTIPLIER: u64 =
        AccessKeyOriginal::ACCESS_KEY_NONCE_RANGE_MULTIPLIER;

    /// Returns:
    ///     AccessKey.
    #[staticmethod]
    pub fn full_access() -> Self {
        AccessKeyOriginal::full_access().into()
    }
}

pybytes_general_via_borsh!(AccessKey);
py_from_bytes_general_via_borsh!(AccessKey);
impl RichcmpEqualityOnly for AccessKey {}
impl Display for AccessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
common_methods_default!(AccessKey);

/// Defines permissions for AccessKey
#[derive(PartialEq, Eq, Hash, Clone, Debug, FromPyObject, EnumIntoPy)]
pub enum AccessKeyPermission {
    FunctionCall(FunctionCallPermission),
    Fieldless(AccessKeyPermissionFieldless),
}

impl From<AccessKeyPermissionOriginal> for AccessKeyPermission {
    fn from(p: AccessKeyPermissionOriginal) -> Self {
        match p {
            AccessKeyPermissionOriginal::FullAccess => {
                Self::Fieldless(AccessKeyPermissionFieldless::FullAccess)
            }
            AccessKeyPermissionOriginal::FunctionCall(p) => Self::FunctionCall(p.into()),
        }
    }
}

impl From<AccessKeyPermission> for AccessKeyPermissionOriginal {
    fn from(p: AccessKeyPermission) -> Self {
        match p {
            AccessKeyPermission::Fieldless(v) => match v {
                AccessKeyPermissionFieldless::FullAccess => Self::FullAccess,
            },
            AccessKeyPermission::FunctionCall(p) => Self::FunctionCall(p.into()),
        }
    }
}

#[pyclass(module = "pyonear.account")]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccessKeyPermissionFieldless {
    FullAccess,
}

impl PyHash for AccessKeyPermissionFieldless {}

#[pyhash]
#[pymethods]
impl AccessKeyPermissionFieldless {}

/// Grants limited permission to make transactions with FunctionCallActions
/// The permission can limit the allowed balance to be spent on the prepaid gas.
/// It also restrict the account ID of the receiver for this function call.
/// It also can restrict the method name for the allowed function calls.
#[pyclass(module = "pyonear.account", subclass)]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Debug,
    From,
    Into,
)]
pub struct FunctionCallPermission(pub FunctionCallPermissionOriginal);

impl PyHash for FunctionCallPermission {}

#[richcmp_eq_only]
#[common_methods]
#[pyhash]
#[pymethods]
impl FunctionCallPermission {
    #[new]
    pub fn new(receiver_id: String, method_names: Vec<String>, allowance: Option<Balance>) -> Self {
        FunctionCallPermissionOriginal {
            allowance,
            receiver_id,
            method_names,
        }
        .into()
    }

    /// int | None: Allowance is a balance limit to use by this access key to pay for function call gas and
    /// transaction fees. When this access key is used, both account balance and the allowance is
    /// decreased by the same value.
    /// `None` means unlimited allowance.
    /// NOTE: To change or increase the allowance, the old access key needs to be deleted and a new
    /// access key should be created.
    #[getter]
    pub fn allowance(&self) -> Option<Balance> {
        self.0.allowance
    }

    // str: This isn't an AccountId because already existing records in testnet genesis have invalid
    // values for this field (see: https://github.com/near/nearcore/pull/4621#issuecomment-892099860)
    // we accomodate those by using a string, allowing us to read and parse genesis.
    /// The access key only allows transactions with the given receiver's account id.
    #[getter]
    pub fn receiver_id(&self) -> String {
        self.0.receiver_id.clone()
    }

    /// list[str]: A list of method names that can be used. The access key only allows transactions with the
    /// function call of one of the given method names.
    /// Empty list means any method name can be used.
    #[getter]
    pub fn method_names(&self) -> Vec<String> {
        self.0.method_names.clone()
    }
}

impl Display for FunctionCallPermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl RichcmpEqualityOnly for FunctionCallPermission {}
common_methods_default!(FunctionCallPermission);
pybytes_general_via_borsh!(FunctionCallPermission);
py_from_bytes_general_via_borsh!(FunctionCallPermission);

pub(crate) fn create_account_mod(py: Python<'_>) -> PyResult<&PyModule> {
    let m = PyModule::new(py, "account")?;
    add_classes!(
        m,
        FunctionCallPermission,
        AccessKeyPermissionFieldless,
        FunctionCallPermission,
        FunctionCallPermission,
        AccessKey,
        Account,
        AccountVersion
    );
    add_union!(
        "AccessKeyPermission",
        m,
        py,
        FunctionCallPermission,
        AccessKeyPermissionFieldless
    )?;
    Ok(m)
}
