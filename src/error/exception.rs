use derive_more::{From, Into};
use near_crypto;

use pyo3::{
    create_exception,
    exceptions::{PyException, PyValueError},
};
use pyo3::{prelude::*, PyTypeInfo};

pub fn to_py_err<T: Into<PyErrWrapper>>(e: T) -> PyErr {
    let wrapped: PyErrWrapper = e.into();
    wrapped.into()
}

pub fn handle_py_err<T: Into<P>, E: ToString + Into<PyErrWrapper>, P>(
    res: Result<T, E>,
) -> PyResult<P> {
    res.map_or_else(|e| Err(to_py_err(e)), |v| Ok(v.into()))
}

pub fn to_py_value_err(err: &impl ToString) -> PyErr {
    PyValueError::new_err(err.to_string())
}

pub fn handle_py_value_err<T: Into<P>, E: ToString, P>(res: Result<T, E>) -> PyResult<P> {
    res.map_or_else(|e| Err(to_py_value_err(&e)), |v| Ok(v.into()))
}

create_exception!(
    pyonear,
    ParseKeyError,
    PyException,
    "Raised when an error is encountered parsing a cryptographic key."
);

create_exception!(
    pyonear,
    ParseSignatureError,
    PyException,
    "Raised when an error is encountered parsing a cryptographic signature."
);

create_exception!(
    pyonear,
    TryFromSliceError,
    PyException,
    "Raised when conversion from a slice to an array fails."
);

create_exception!(
    pyonear,
    Secp256K1Error,
    PyException,
    "Raised when an error is encountered in the secp256k1 library."
);

#[derive(From, Into)]
pub struct PyErrWrapper(pub PyErr);

macro_rules! to_py_err_wrapper {
    ($src:ty, $python_err:ty) => {
        impl From<$src> for PyErrWrapper {
            fn from(e: $src) -> Self {
                type PythonErrType = $python_err;
                Self(PythonErrType::new_err(e.to_string()))
            }
        }
    };
}

to_py_err_wrapper!(near_crypto::ParseKeyError, ParseKeyError);
to_py_err_wrapper!(near_crypto::ParseSignatureError, ParseSignatureError);
to_py_err_wrapper!(std::array::TryFromSliceError, TryFromSliceError);
to_py_err_wrapper!(secp256k1::Error, Secp256K1Error);

pub(crate) fn create_exception_mod(py: Python<'_>) -> PyResult<&PyModule> {
    let m = PyModule::new(py, "exception")?;
    m.add("ParseKeyError", ParseKeyError::type_object(py))?;
    m.add("ParseSignatureError", ParseSignatureError::type_object(py))?;
    m.add("TryFromSliceError", TryFromSliceError::type_object(py))?;
    m.add("Secp256K1Error", Secp256K1Error::type_object(py))?;
    Ok(m)
}
