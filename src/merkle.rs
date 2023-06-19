use crate::{crypto_hash::CryptoHash, hash_enum, quick_struct_boilerplate_core};
use near_primitives::merkle::{
    Direction as DirectionOriginal, MerklePathItem as MerklePathItemOriginal,
};
use pyo3::prelude::*;
use solders_macros::{common_methods, enum_original_mapping, richcmp_eq_only};
use solders_traits::impl_display;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[pyclass(module = "pyonear.merkle")]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[enum_original_mapping(DirectionOriginal)]
pub enum Direction {
    Left,
    Right,
}
hash_enum!(Direction);


#[pyclass(module = "pyonear.merkle", subclass)]
#[derive(PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize, serde::Deserialize, serde::Serialize)]
pub struct MerklePathItem(pub MerklePathItemOriginal);


#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl MerklePathItem {
    #[new]
    pub fn new(hash: CryptoHash, direction: Direction) -> Self {
        MerklePathItemOriginal {
            hash: hash.into(),
            direction: direction.into(),
        }
        .into()
    }

    /// CryptoHash: the hash field of the item.
    #[getter]
    pub fn hash(&self) -> CryptoHash {
        self.0.hash.into()
    }

    /// Direction: the direction.
    #[getter]
    pub fn direction(&self) -> Direction {
        self.0.direction.clone().into()
    }
}
impl_display!(MerklePathItem);
quick_struct_boilerplate_core!(MerklePathItem);

pub(crate) fn create_merkle_mod(py: Python<'_>) -> PyResult<&PyModule> {
    let m = PyModule::new(py, "merkle")?;
    m.add_class::<MerklePathItem>()?;
    m.add_class::<Direction>()?;
    Ok(m)
}
