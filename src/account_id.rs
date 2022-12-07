use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{Display, From, Into};
use near_primitives::account::id as near_account_id;
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use solders_macros::{common_methods, pyhash, richcmp_eq_only};
use solders_traits::{common_methods_default, PyHash, RichcmpEqualityOnly};

use crate::{
    error::exception::handle_py_value_err, py_from_bytes_general_via_borsh,
    pybytes_general_via_borsh,
};

/// NEAR Account Identifier.
///
/// This is a unique, syntactically valid, human-readable account identifier on the NEAR network.
///
///
/// Example:
///
///     >>> from pyonear.account_id import AccountId
///     >>> alice = AccountId("alice.near")
///     >>> AccountId("ƒelicia.near") # (ƒ is not f)
///     Traceback (most recent call last):
///       File "<stdin>", line 1, in <module>
///     ValueError: the Account ID contains an invalid character 'ƒ' at index 0
///
#[pyclass(module = "pyonear.account_id", subclass)]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    From,
    Into,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Display,
)]
pub struct AccountId(pub near_account_id::AccountId);

impl RichcmpEqualityOnly for AccountId {}
pybytes_general_via_borsh!(AccountId);
py_from_bytes_general_via_borsh!(AccountId);
common_methods_default!(AccountId);
impl PyHash for AccountId {}
impl AsRef<near_account_id::AccountId> for AccountId {
    fn as_ref(&self) -> &near_account_id::AccountId {
        &self.0
    }
}

#[richcmp_eq_only]
#[common_methods]
#[pyhash]
#[pymethods]
impl AccountId {
    /// Shortest valid length for a NEAR Account ID.
    #[classattr]
    pub const MIN_LEN: usize = near_account_id::AccountId::MIN_LEN;
    /// Longest valid length for a NEAR Account ID.
    #[classattr]
    pub const MAX_LEN: usize = near_account_id::AccountId::MAX_LEN;
    #[new]
    pub fn new(account_id: &str) -> PyResult<Self> {
        handle_py_value_err(near_account_id::AccountId::from_str(account_id))
    }
    /// Returns ``True`` if the ``AccountId`` is a top-level NEAR Account ID.
    ///
    /// See `Top-level Accounts <https://docs.near.org/docs/concepts/account#top-level-accounts>`_.
    ///
    /// Example:
    ///
    ///     >>> from pyonear.account_id import AccountId
    ///     >>> AccountId("near").is_top_level()
    ///     True
    ///     >>> AccountId("alice").is_top_level()
    ///     True
    ///     >>> AccountId("alice.near").is_top_level()
    ///     False
    ///
    pub fn is_top_level(&self) -> bool {
        self.0.is_top_level()
    }

    /// Returns ```True`` if the ``AccountId`` is a direct sub-account of the provided parent account.
    ///
    /// See `Subaccounts <https://docs.near.org/docs/concepts/account#subaccounts>`_.
    ///
    /// Example:
    ///
    ///     >>> from pyonear.account_id import AccountId
    ///     >>> near_tla = AccountId("near")
    ///     >>> near_tla.is_top_level()
    ///     True
    ///     >>> alice = AccountId("alice.near")
    ///     >>> alice.is_sub_account_of(near_tla)
    ///     True
    ///     >>> alice_app = AccountId("app.alice.near")
    ///     >>> alice_app.is_sub_account_of(alice)
    ///     True
    ///     >>> alice_app.is_sub_account_of(near_tla)
    ///     False
    ///
    pub fn is_sub_account_of(&self, parent: &AccountId) -> bool {
        self.0.is_sub_account_of(parent.as_ref())
    }

    /// Returns ``True`` if the ``AccountId`` is a 64 characters long hexadecimal.
    ///
    /// See `Implicit-Accounts <https://docs.near.org/docs/concepts/account#implicit-accounts>`_.
    ///
    /// Example:
    ///
    ///     >>> from pyonear.account_id import AccountId
    ///     >>> AccountId("alice.near").is_implicit()
    ///     False
    ///     >>> rando = AccountId("98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de")
    ///     >>> rando.is_implicit()
    ///     True
    ///
    pub fn is_implicit(&self) -> bool {
        self.0.is_implicit()
    }

    /// Returns ``True`` if this ``AccountId`` is the system account.
    ///
    /// See `System account <https://nomicon.io/DataStructures/Account.html?highlight=system#system-account>`_.
    ///
    /// Example:
    ///
    ///     >>> from pyonear.account_id import AccountId
    ///     >>> AccountId("alice.near").is_system()
    ///     False
    ///     >>> AccountId("system").is_system()
    ///     True
    ///
    pub fn is_system(&self) -> bool {
        self.0.is_system()
    }

    /// Validates a string as a well-structured NEAR Account ID.
    ///
    /// Checks Account ID validity without constructing an ``AccountId`` instance.
    ///
    /// Example:
    ///
    ///     >>> from pyonear.account_id import AccountId
    ///     >>> AccountId.validate("alice.near")
    ///     >>> AccountId.validate("ƒelicia.near")
    ///     Traceback (most recent call last):
    ///       File "<stdin>", line 1, in <module>
    ///     ValueError: the Account ID contains an invalid character 'ƒ' at index 0
    ///
    #[staticmethod]
    pub fn validate(account_id: &str) -> PyResult<()> {
        handle_py_value_err(near_account_id::AccountId::validate(account_id))
    }
}

pub(crate) fn create_account_id_mod(py: Python<'_>) -> PyResult<&PyModule> {
    let m = PyModule::new(py, "account_id")?;
    m.add_class::<AccountId>()?;
    Ok(m)
}
