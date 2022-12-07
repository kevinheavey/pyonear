//! These docstrings are written for Python users.
//!
//! If you're viewing them on docs.rs, the formatting won't make much sense.
pub mod account;
pub mod account_id;
pub mod config;
pub mod crypto;
pub mod crypto_hash;
pub mod error;
pub mod merkle;
pub mod traits;
pub mod transaction;
use std::collections::HashMap;

use account::create_account_mod;
use account_id::create_account_id_mod;
use config::create_config_mod;
use crypto::create_crypto_mod;
use crypto_hash::create_crypto_hash_mod;
use error::create_error_mod;
use merkle::create_merkle_mod;
use pyo3::{
    prelude::*,
    types::{PyTuple, PyType},
};
use transaction::create_transaction_mod;

#[macro_export]
macro_rules! quick_struct {
    ($name:ident, $doc:literal, $module:literal, $($element:ident: $ty:ty),*) => {
        #[doc=$doc]
        #[derive(
            Clone,
            Debug,
            PartialEq,
            Eq,
            Hash,
            serde::Serialize,
            serde::Deserialize,
            borsh::BorshSerialize,
            borsh::BorshDeserialize,
        )]
        #[pyclass(module=$module, subclass, get_all)]
        pub struct $name { $(pub $element: $ty),* }
        #[solders_macros::common_methods]
        #[solders_macros::pyhash]
        #[solders_macros::richcmp_eq_only]
        #[pymethods]
        impl $name {
            #[new]
            pub fn new($($element: $ty),*) -> Self {
                Self { $( $element ),* }
            }
        }
        $crate::quick_struct_boilerplate!($name);
    }
}

#[macro_export]
macro_rules! quick_struct_boilerplate_core_no_json {
    ($name:ident) => {
        impl solders_traits::RichcmpEqualityOnly for $name {}
        impl solders_traits::CommonMethodsCore for $name {}
        $crate::pybytes_general_via_borsh!($name);
        $crate::py_from_bytes_general_via_borsh!($name);
    };
}

#[macro_export]
macro_rules! quick_struct_boilerplate_core {
    ($name:ident) => {
        $crate::quick_struct_boilerplate_core_no_json!($name);
        impl solders_traits::CommonMethods<'_> for $name {}
    };
}

#[macro_export]
macro_rules! quick_struct_boilerplate {
    ($name:ident) => {
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:?}", self)
            }
        }
        impl solders_traits::PyHash for $name {}
        $crate::quick_struct_boilerplate_core!($name);
    };
}

#[macro_export]
macro_rules! quick_struct_length_limit {
    ($name:ident, $doc:literal, $module:literal) => {
        $crate::quick_struct!($name, $doc, $module, length: u64, limit: u64);
    };
}
#[macro_export]
macro_rules! quick_struct_size_limit {
    ($name:ident, $doc:literal, $module:literal) => {
        $crate::quick_struct!($name, $doc, $module, size: u64, limit: u64);
    };
}
#[macro_export]
macro_rules! hash_enum {
    ($ty:ty) => {
        impl solders_traits::PyHash for $ty {}

        #[solders_macros::pyhash]
        #[pymethods]
        impl $ty {}
    };
}

fn add_union_to_module(
    name: &str,
    m: &PyModule,
    py: Python,
    members: Vec<&PyType>,
) -> PyResult<()> {
    let typing = py.import("typing")?;
    let union = typing.getattr("Union")?;
    m.add(name, union.get_item(PyTuple::new(py, members.clone()))?)
}

#[macro_export]
macro_rules! vec_type_object {
    ($py:expr, $($member:ty),*) => {
        vec![$(<$member as pyo3::PyTypeInfo>::type_object($py)),*]
    };
}

#[macro_export]
macro_rules! add_union {
    ($name:literal, $m:expr, $py:expr, $($member:ty),*) => {
        $crate::add_union_to_module($name, $m, $py, $crate::vec_type_object!($py, $($member),*))
    };
}

#[macro_export]
macro_rules! add_classes {
    ($m:expr, $($member:ty),*) => {
        $($m.add_class::<$member>()?;)*
    };
}
#[pymodule]
fn pyonear(py: Python, m: &PyModule) -> PyResult<()> {
    let error_mod = create_error_mod(py)?;
    let account_id_mod = create_account_id_mod(py)?;
    let account_mod = create_account_mod(py)?;
    let config_mod = create_config_mod(py)?;
    let crypto_hash_mod = create_crypto_hash_mod(py)?;
    let crypto_mod = create_crypto_mod(py)?;
    let merkle_mod = create_merkle_mod(py)?;
    let transaction_mod = create_transaction_mod(py)?;
    let submodules = [
        error_mod,
        account_id_mod,
        account_mod,
        config_mod,
        crypto_hash_mod,
        crypto_mod,
        merkle_mod,
        transaction_mod,
    ];
    let modules: HashMap<String, &PyModule> = submodules
        .iter()
        .map(|x| (format!("pyonear.{}", x.name().unwrap()), *x))
        .collect();
    let sys_modules = py.import("sys")?.getattr("modules")?;
    sys_modules.call_method1("update", (modules,))?;
    for submod in submodules {
        m.add_submodule(submod)?;
    }
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
