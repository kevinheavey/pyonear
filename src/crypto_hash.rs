use borsh::{BorshDeserialize, BorshSerialize};
use pyo3::{exceptions::PyValueError, prelude::*};
use serde::{Deserialize, Serialize};
use solders_macros::{common_methods, pyhash, richcmp_eq_only};
use solders_traits::{
    common_methods_default, pybytes_general_via_slice, PyFromBytesGeneral, PyHash,
    RichcmpEqualityOnly,
};
use std::hash::Hash;
use std::str::FromStr;

use near_primitives::hash::{hash as hash_original, CryptoHash as CryptoHashOriginal};

#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Hash,
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
    derive_more::AsRef,
    derive_more::From,
    derive_more::Into,
    derive_more::Display,
)]
#[as_ref(forward)]
#[pyclass(module = "pyonear.crypto_hash", subclass)]
pub struct CryptoHash(pub CryptoHashOriginal);

#[richcmp_eq_only]
#[common_methods]
#[pyhash]
#[pymethods]
impl CryptoHash {
    #[new]
    pub fn new(data: [u8; 32]) -> Self {
        CryptoHashOriginal(data).into()
    }

    /// Initialize a CryptoHash as 32 * 0 bytes.
    #[staticmethod]
    pub fn zero() -> Self {
        CryptoHashOriginal::new().into()
    }

    /// Calculates hash of given bytes.
    #[staticmethod]
    pub fn hash_bytes(data: &[u8]) -> Self {
        CryptoHashOriginal::hash_bytes(data).into()
    }

    /// Parse from a string.
    ///
    /// s (str): The string to parse
    ///
    /// Returns:
    ///    CryptoHash
    #[staticmethod]
    #[pyo3(name = "from_str")]
    pub fn new_from_str(s: &str) -> PyResult<Self> {
        let underlying =
            CryptoHashOriginal::from_str(s).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(underlying.into())
    }

    /// Build a new CryptoHash using the Rust ``Default`` trait.
    ///
    /// Returns:
    ///     CryptoHash
    #[staticmethod]
    #[pyo3(name = "default")]
    pub fn new_default() -> Self {
        Self::default()
    }
}

pybytes_general_via_slice!(CryptoHash);
impl RichcmpEqualityOnly for CryptoHash {}
common_methods_default!(CryptoHash);
impl PyHash for CryptoHash {}

impl PyFromBytesGeneral for CryptoHash {
    fn py_from_bytes_general(raw: &[u8]) -> PyResult<Self> {
        let underlying =
            CryptoHashOriginal::try_from(raw).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(underlying.into())
    }
}

impl Default for CryptoHash {
    fn default() -> Self {
        CryptoHashOriginal::default().into()
    }
}

/// Calculates a hash of a bytes slice.
///
/// The example below calculates the hash of the indicated data.
///
/// Example:
///
///     >>> from pyonear.crypto_hash import crypto_hash
///     >>> crypto_hash(bytes([1, 2, 3]))
///     CryptoHash(
///         `EutHBsdT1YCzHxjCfQHnLPL1vFrkSyLSio4vkphfnEk`,
///     )
///
#[pyfunction]
pub fn crypto_hash(data: &[u8]) -> CryptoHash {
    hash_original(data).into()
}

pub(crate) fn create_crypto_hash_mod(py: Python<'_>) -> PyResult<&PyModule> {
    let m = PyModule::new(py, "crypto_hash")?;
    m.add_class::<CryptoHash>()?;
    m.add_function(wrap_pyfunction!(crypto_hash, m)?)?;
    Ok(m)
}
