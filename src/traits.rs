use borsh::{BorshDeserialize, BorshSerialize};
use pyo3::{prelude::*, types::PyBytes};

use crate::error::exception::handle_py_value_err;

pub trait PyBytesBorsh: BorshSerialize {
    fn pybytes_borsh<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        PyBytes::new(py, &borsh::to_vec(self).unwrap())
    }
}

pub trait PyFromBytesBorsh: BorshDeserialize {
    fn py_from_bytes_borsh(raw: &[u8]) -> PyResult<Self> {
        let deser = Self::try_from_slice(raw);
        handle_py_value_err(deser)
    }
}

#[macro_export]
macro_rules! pybytes_general_for_pybytes_borsh {
    ($ident:ident) => {
        impl solders_traits::PyBytesGeneral for $ident {
            fn pybytes_general<'a>(
                &self,
                py: pyo3::prelude::Python<'a>,
            ) -> &'a pyo3::types::PyBytes {
                $crate::traits::PyBytesBorsh::pybytes_borsh(self, py)
            }
        }
    };
}

#[macro_export]
macro_rules! pybytes_general_via_borsh {
    ($ident:ident) => {
        impl $crate::traits::PyBytesBorsh for $ident {}
        $crate::pybytes_general_for_pybytes_borsh!($ident);
    };
}

#[macro_export]
macro_rules! py_from_bytes_general_for_py_from_bytes_borsh {
    ($ident:ident) => {
        impl solders_traits::PyFromBytesGeneral for $ident {
            fn py_from_bytes_general(raw: &[u8]) -> PyResult<Self> {
                $crate::traits::PyFromBytesBorsh::py_from_bytes_borsh(raw)
            }
        }
    };
}

#[macro_export]
macro_rules! py_from_bytes_general_via_borsh {
    ($ident:ident) => {
        impl $crate::traits::PyFromBytesBorsh for $ident {}
        $crate::py_from_bytes_general_for_py_from_bytes_borsh!($ident);
    };
}
