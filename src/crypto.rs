use std::{
    array::TryFromSliceError,
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    io::{Error, Write},
    path::PathBuf,
    str::FromStr,
};

use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{AsRef, From, Into};
use ed25519_dalek;
use near_crypto::{self, Signer as SignerTrait};
use pyo3::{
    exceptions::{PyIOError, PyValueError},
    prelude::*,
    types::PyBytes,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, TryFromInto};
use solders_macros::{common_methods, pyhash, richcmp_eq_only, EnumIntoPy};
use solders_traits::{
    common_methods_default, py_from_bytes_general_via_bincode, pybytes_general_via_bincode,
    pybytes_general_via_slice, PyBytesGeneral, PyFromBytesGeneral, PyHash, RichcmpEqualityOnly,
};

use crate::{
    account_id::AccountId,
    add_classes, add_union,
    error::exception::{handle_py_err, to_py_err},
};
macro_rules! crypto_common_boilerplate {
    ($name:ident, $underlying_enum:ty, $inner:ty, $py_enum:ty) => {
        impl PyFromBytesGeneral for $name {
            fn py_from_bytes_general(raw: &[u8]) -> PyResult<Self> {
                handle_py_err(Self::try_from(raw))
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}", <$underlying_enum>::from(self))
            }
        }
        impl From<$inner> for $py_enum {
            fn from(p: $inner) -> Self {
                $name::from(p).into()
            }
        }
        impl RichcmpEqualityOnly for $name {}
        impl PyHash for $name {}
        common_methods_default!($name);
    };
}

macro_rules! impl_from_str {
    ($ty:ty, $underlying_ty:ty, $path:path) => {
        impl FromStr for $ty {
            type Err = PyErr;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                type Underlying = $underlying_ty;
                let underlying = Underlying::from_str(s).map_err(to_py_err)?;
                match underlying {
                    $path(p) => Ok(p.into()),
                    _ => Err(PyValueError::new_err("Parsed unexpected key type.")),
                }
            }
        }
    };
}

macro_rules! pubkey_boilerplate {
    ($name:ident, $underlying_enum:ty, $underlying_variant:path) => {
        #[pyclass(module = "pyonear.crypto", subclass)]
        #[serde_as]
        #[derive(Clone, Debug, PartialEq, Eq, From, Into, AsRef, Serialize, Deserialize)]
        #[as_ref(forward)]
        pub struct $name(#[serde_as(as = "TryFromInto<PublicKey>")] pub near_crypto::$name);
        impl TryFrom<&[u8]> for $name {
            type Error = near_crypto::ParseKeyError;
            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                near_crypto::$name::try_from(value).map($name::from)
            }
        }

        pybytes_general_via_slice!($name);
        crypto_common_boilerplate!($name, $underlying_enum, near_crypto::$name, PublicKey);
        #[allow(clippy::derive_hash_xor_eq)]
        impl Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.0.as_ref().hash(state);
            }
        }
        impl_from_str!($name, $underlying_enum, $underlying_variant);
    };
}

macro_rules! secret_key_boilerplate {
    ($name:ident, $inner:ty, $underlying_enum:ty, $underlying_variant:path) => {
        #[pyclass(module = "pyonear.crypto", subclass)]
        #[serde_as]
        #[derive(Clone, Debug, PartialEq, Eq, From, Into, Serialize, Deserialize)]
        pub struct $name(#[serde_as(as = "TryFromInto<SecretKey>")] pub $inner);
        pybytes_general_via_slice!($name);
        crypto_common_boilerplate!($name, $underlying_enum, $inner, SecretKey);
        impl_from_str!($name, $underlying_enum, $underlying_variant);
    };
}

macro_rules! signature_boilerplate {
    ($name:ident, $inner:ty, $underlying_enum:ty, $underlying_variant:path) => {
        #[pyclass(module = "pyonear.crypto", subclass)]
        #[serde_as]
        #[derive(Clone, Debug, PartialEq, Eq, From, Into, Serialize, Deserialize)]
        pub struct $name(#[serde_as(as = "TryFromInto<Signature>")] pub $inner);
        #[allow(clippy::derive_hash_xor_eq)]
        impl Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                near_crypto::Signature::from(self).hash(state);
            }
        }
        crypto_common_boilerplate!($name, $underlying_enum, $inner, Signature);
        impl_from_str!($name, $underlying_enum, $underlying_variant);
    };
}

pubkey_boilerplate!(
    ED25519PublicKey,
    near_crypto::PublicKey,
    near_crypto::PublicKey::ED25519
);
pubkey_boilerplate!(
    Secp256K1PublicKey,
    near_crypto::PublicKey,
    near_crypto::PublicKey::SECP256K1
);
secret_key_boilerplate!(
    ED25519SecretKey,
    near_crypto::ED25519SecretKey,
    near_crypto::SecretKey,
    near_crypto::SecretKey::ED25519
);
secret_key_boilerplate!(
    Secp256K1SecretKey,
    secp256k1::SecretKey,
    near_crypto::SecretKey,
    near_crypto::SecretKey::SECP256K1
);
signature_boilerplate!(
    ED25519Signature,
    ed25519_dalek::Signature,
    near_crypto::Signature,
    near_crypto::Signature::ED25519
);
signature_boilerplate!(
    Secp256K1Signature,
    near_crypto::Secp256K1Signature,
    near_crypto::Signature,
    near_crypto::Signature::SECP256K1
);
pybytes_general_via_slice!(ED25519Signature);

#[derive(Clone, PartialEq, Eq, From, Serialize, Deserialize, FromPyObject, EnumIntoPy)]
#[serde(from = "near_crypto::PublicKey", into = "near_crypto::PublicKey")]
pub enum PublicKey {
    ED25519(ED25519PublicKey),
    SECP256K1(Secp256K1PublicKey),
}

impl BorshSerialize for PublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        BorshSerialize::serialize(&near_crypto::PublicKey::from(self), writer)
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize(buf: &mut &[u8]) -> Result<Self, Error> {
        let underlying: near_crypto::PublicKey = BorshDeserialize::deserialize(buf)?;
        Ok(underlying.into())
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let underlying = near_crypto::PublicKey::from(self);
        Debug::fmt(&underlying, f)
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        near_crypto::PublicKey::from(self).hash(state)
    }
}

macro_rules! crypto_enum_convert {
    ($new:ty, $underlying:ty) => {
        impl From<$new> for $underlying {
            fn from(p: $new) -> Self {
                type P = $new;
                match p {
                    P::ED25519(v) => Self::ED25519(v.into()),
                    P::SECP256K1(v) => Self::SECP256K1(v.into()),
                }
            }
        }
        impl From<$underlying> for $new {
            fn from(p: $underlying) -> Self {
                type P = $underlying;
                match p {
                    P::ED25519(v) => Self::ED25519(v.into()),
                    P::SECP256K1(v) => Self::SECP256K1(v.into()),
                }
            }
        }
    };
}

crypto_enum_convert!(PublicKey, near_crypto::PublicKey);
crypto_enum_convert!(SecretKey, near_crypto::SecretKey);
crypto_enum_convert!(Signature, near_crypto::Signature);

impl From<&ED25519PublicKey> for near_crypto::PublicKey {
    fn from(p: &ED25519PublicKey) -> Self {
        Self::ED25519(near_crypto::ED25519PublicKey(p.0 .0))
    }
}

impl From<&Secp256K1PublicKey> for near_crypto::PublicKey {
    fn from(p: &Secp256K1PublicKey) -> Self {
        let bytes: [u8; 64] = p.0.as_ref().try_into().unwrap();
        Self::SECP256K1(near_crypto::Secp256K1PublicKey::from(bytes))
    }
}

impl From<&PublicKey> for near_crypto::PublicKey {
    fn from(p: &PublicKey) -> Self {
        match p {
            PublicKey::ED25519(x) => near_crypto::PublicKey::from(x),
            PublicKey::SECP256K1(x) => near_crypto::PublicKey::from(x),
        }
    }
}

macro_rules! unwrap_enum {
    ($target: expr, $pat: path) => {{
        if let $pat(a) = $target {
            a.into()
        } else {
            panic!("mismatch variant when cast to {}", stringify!($pat));
        }
    }};
}

macro_rules! try_from_enum_to_underlying {
    ($enum:ty, $underlying:ty, $path:path) => {
        impl TryFrom<$enum> for $underlying {
            type Error = &'static str;

            fn try_from(value: $enum) -> Result<Self, Self::Error> {
                match value {
                    $path(v) => Ok(v.into()),
                    _ => Err("Unexpected key type"),
                }
            }
        }
    };
}

try_from_enum_to_underlying!(PublicKey, near_crypto::ED25519PublicKey, PublicKey::ED25519);
try_from_enum_to_underlying!(
    PublicKey,
    near_crypto::Secp256K1PublicKey,
    PublicKey::SECP256K1
);

#[pyhash]
#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl ED25519PublicKey {
    #[classattr]
    pub const LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

    #[new]
    pub fn new(key_bytes: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH]) -> Self {
        near_crypto::ED25519PublicKey(key_bytes).into()
    }

    /// Create an empty pubkey.
    ///
    /// Returns:
    ///     ED25519PublicKey
    #[staticmethod]
    pub fn empty() -> Self {
        unwrap_enum!(
            near_crypto::PublicKey::empty(near_crypto::KeyType::ED25519),
            near_crypto::PublicKey::ED25519
        )
    }

    /// Build from seed.
    ///
    /// Args:
    ///     seed (str)
    ///
    /// Returns:
    ///     ED25519PublicKey
    #[staticmethod]
    pub fn from_seed(seed: &str) -> Self {
        unwrap_enum!(
            near_crypto::PublicKey::from_seed(near_crypto::KeyType::ED25519, seed,),
            near_crypto::PublicKey::ED25519
        )
    }

    /// Parse from a string.
    ///
    /// s (str): The string to parse
    ///
    /// Returns:
    ///    ED25519PublicKey
    #[staticmethod]
    #[pyo3(name = "from_str")]
    pub fn new_from_str(s: &str) -> PyResult<Self> {
        Self::from_str(s)
    }
}

#[pyhash]
#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl Secp256K1PublicKey {
    #[classattr]
    pub const LENGTH: usize = 64;

    #[new]
    pub fn new(key_bytes: [u8; Self::LENGTH]) -> Self {
        near_crypto::Secp256K1PublicKey::from(key_bytes).into()
    }

    /// Create an empty pubkey.
    ///
    /// Returns:
    ///     Secp256K1PublicKey
    #[staticmethod]
    pub fn empty() -> Self {
        unwrap_enum!(
            near_crypto::PublicKey::empty(near_crypto::KeyType::SECP256K1),
            near_crypto::PublicKey::SECP256K1
        )
    }

    /// Parse from a string.
    ///
    /// s (str): The string to parse
    ///
    /// Returns:
    ///    Secp256K1PublicKey
    #[staticmethod]
    #[pyo3(name = "from_str")]
    pub fn new_from_str(s: &str) -> PyResult<Self> {
        Self::from_str(s)
    }
}

/// Secret key container supporting different curves.
#[derive(Clone, PartialEq, Eq, From, Serialize, Deserialize, FromPyObject, Debug, EnumIntoPy)]
#[serde(from = "near_crypto::SecretKey", into = "near_crypto::SecretKey")]
pub enum SecretKey {
    ED25519(ED25519SecretKey),
    SECP256K1(Secp256K1SecretKey),
}

try_from_enum_to_underlying!(SecretKey, near_crypto::ED25519SecretKey, SecretKey::ED25519);
try_from_enum_to_underlying!(SecretKey, secp256k1::SecretKey, SecretKey::SECP256K1);

impl AsRef<[u8]> for ED25519SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0 .0
    }
}

impl AsRef<[u8]> for Secp256K1SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<&[u8]> for ED25519SecretKey {
    type Error = TryFromSliceError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let as_array: [u8; ed25519_dalek::KEYPAIR_LENGTH] = value.try_into()?;
        Ok(near_crypto::ED25519SecretKey(as_array).into())
    }
}

impl TryFrom<&[u8]> for Secp256K1SecretKey {
    type Error = secp256k1::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let underlying = secp256k1::SecretKey::from_slice(value)?;
        Ok(underlying.into())
    }
}

impl From<&ED25519SecretKey> for near_crypto::SecretKey {
    fn from(s: &ED25519SecretKey) -> Self {
        Self::ED25519(near_crypto::ED25519SecretKey(s.0 .0))
    }
}

impl From<&Secp256K1SecretKey> for near_crypto::SecretKey {
    fn from(s: &Secp256K1SecretKey) -> Self {
        Self::SECP256K1(secp256k1::SecretKey::from_slice(s.0.as_ref()).unwrap())
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Secp256K1SecretKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_ref().hash(state);
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for ED25519SecretKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0 .0.hash(state);
    }
}

#[pyhash]
#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl ED25519SecretKey {
    #[classattr]
    pub const LENGTH: usize = 64;

    #[new]
    pub fn new(key_bytes: [u8; 64]) -> Self {
        near_crypto::ED25519SecretKey(key_bytes).into()
    }

    /// Randomly generate the key.
    ///
    /// Returns:
    ///     ED25519SecretKey
    #[staticmethod]
    pub fn from_random() -> Self {
        unwrap_enum!(
            near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519,),
            near_crypto::SecretKey::ED25519
        )
    }

    /// Sign a message with this secret key.
    ///
    /// Args:
    ///     data (bytes | Sequence[int]): The message to sign.
    ///
    /// Returns
    ///     ED25519Signature: the message signature.
    pub fn sign(&self, data: &[u8]) -> ED25519Signature {
        let sk = near_crypto::SecretKey::from(self);
        unwrap_enum!(sk.sign(data), near_crypto::Signature::ED25519)
    }

    /// Parse from a string.
    ///
    /// s (str): The string to parse
    ///
    /// Returns:
    ///    ED25519SecretKey
    #[staticmethod]
    #[pyo3(name = "from_str")]
    pub fn new_from_str(s: &str) -> PyResult<Self> {
        Self::from_str(s)
    }

    /// Build from seed.
    ///
    /// Args:
    ///     seed (str)
    ///
    /// Returns:
    ///     ED25519SecretKey
    #[staticmethod]
    pub fn from_seed(seed: &str) -> Self {
        unwrap_enum!(
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, seed),
            near_crypto::SecretKey::ED25519
        )
    }

    /// Retrieve the public key of this secret key.
    ///
    /// Returns:
    ///     ED25519PublicKey: The public key.
    pub fn public_key(&self) -> ED25519PublicKey {
        unwrap_enum!(
            near_crypto::SecretKey::from(self).public_key(),
            near_crypto::PublicKey::ED25519
        )
    }
}

#[pyhash]
#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl Secp256K1SecretKey {
    #[classattr]
    pub const LENGTH: usize = secp256k1::constants::SECRET_KEY_SIZE;

    #[new]
    pub fn new(key_bytes: [u8; Self::LENGTH]) -> PyResult<Self> {
        handle_py_err(secp256k1::SecretKey::from_slice(&key_bytes))
    }

    /// Randomly generate the key.
    ///
    /// Returns:
    ///     Secp256K1SecretKey
    #[staticmethod]
    pub fn from_random() -> Self {
        unwrap_enum!(
            near_crypto::SecretKey::from_random(near_crypto::KeyType::SECP256K1),
            near_crypto::SecretKey::SECP256K1
        )
    }

    /// Parse from a string.
    ///
    /// s (str): The string to parse
    ///
    /// Returns:
    ///    Secp256K1SecretKey
    #[staticmethod]
    #[pyo3(name = "from_str")]
    pub fn new_from_str(s: &str) -> PyResult<Self> {
        Self::from_str(s)
    }

    /// Build from seed.
    ///
    /// Args:
    ///     seed (str)
    ///
    /// Returns:
    ///     Secp256K1SecretKey
    #[staticmethod]
    pub fn from_seed(seed: &str) -> Self {
        unwrap_enum!(
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::SECP256K1, seed),
            near_crypto::SecretKey::SECP256K1
        )
    }

    /// Retrieve the public key of this secret key.
    ///
    /// Returns:
    ///     Secp256K1PublicKey: The public key.
    pub fn public_key(&self) -> Secp256K1PublicKey {
        unwrap_enum!(
            near_crypto::SecretKey::from(self).public_key(),
            near_crypto::PublicKey::SECP256K1
        )
    }

    /// Sign a message with this secret key.
    ///
    /// Args:
    ///     data (bytes | Sequence[int]): The message to sign.
    ///
    /// Returns
    ///     Secp256K1Signature: the message signature.
    pub fn sign(&self, data: &[u8]) -> Secp256K1Signature {
        let sk = near_crypto::SecretKey::from(self);
        unwrap_enum!(sk.sign(data), near_crypto::Signature::SECP256K1)
    }
}

#[derive(Clone, PartialEq, Eq, From, Serialize, Deserialize, FromPyObject, EnumIntoPy)]
#[serde(from = "near_crypto::Signature", into = "near_crypto::Signature")]
pub enum Signature {
    ED25519(ED25519Signature),
    SECP256K1(Secp256K1Signature),
}

impl PyBytesGeneral for Secp256K1Signature {
    fn pybytes_general<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        let bytes: &[u8; 65] = &self.0.clone().into();
        PyBytes::new(py, bytes)
    }
}

try_from_enum_to_underlying!(Signature, ed25519_dalek::Signature, Signature::ED25519);
try_from_enum_to_underlying!(
    Signature,
    near_crypto::Secp256K1Signature,
    Signature::SECP256K1
);

impl TryFrom<&[u8]> for ED25519Signature {
    type Error = near_crypto::ParseSignatureError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let underlying = near_crypto::Signature::from_parts(near_crypto::KeyType::ED25519, value)?;
        Ok(unwrap_enum!(underlying, near_crypto::Signature::ED25519))
    }
}

impl TryFrom<&[u8]> for Secp256K1Signature {
    type Error = near_crypto::ParseSignatureError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let underlying =
            near_crypto::Signature::from_parts(near_crypto::KeyType::SECP256K1, value)?;
        Ok(unwrap_enum!(underlying, near_crypto::Signature::SECP256K1))
    }
}
impl AsRef<[u8]> for ED25519Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<&ED25519Signature> for near_crypto::Signature {
    fn from(s: &ED25519Signature) -> Self {
        Self::ED25519(s.0)
    }
}
impl From<&Secp256K1Signature> for near_crypto::Signature {
    fn from(s: &Secp256K1Signature) -> Self {
        let bytes: [u8; 65] = s.0.clone().into();
        Self::SECP256K1(near_crypto::Secp256K1Signature::from(bytes))
    }
}

#[pyhash]
#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl ED25519Signature {
    #[classattr]
    pub const LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;

    #[new]
    pub fn new(sig_bytes: [u8; Self::LENGTH]) -> PyResult<Self> {
        handle_py_err(Self::try_from(sig_bytes.as_ref()))
    }

    /// Create an empty signature.
    ///
    /// Returns:
    ///     ED25519Signature
    #[staticmethod]
    pub fn empty() -> Self {
        unwrap_enum!(
            near_crypto::Signature::empty(near_crypto::KeyType::ED25519),
            near_crypto::Signature::ED25519
        )
    }

    /// Verifies that this signature comes from signing the data with given public key.
    /// Also if public key isn't on the curve returns `false`.
    ///
    /// Args:
    ///     data (Sequence[int] | bytes): the unsigned message.
    ///     public_key (ED25519PublicKey): The public key of the signer.
    ///
    /// Returns:
    ///     bool: Signature verification result
    ///
    pub fn verify(&self, data: &[u8], public_key: &ED25519PublicKey) -> bool {
        let pubkey = near_crypto::PublicKey::from(public_key);
        near_crypto::Signature::from(self).verify(data, &pubkey)
    }

    /// Parse from a string.
    ///
    /// s (str): The string to parse
    ///
    /// Returns:
    ///    ED25519Signature
    #[staticmethod]
    #[pyo3(name = "from_str")]
    pub fn new_from_str(s: &str) -> PyResult<Self> {
        Self::from_str(s)
    }
}

#[pyhash]
#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl Secp256K1Signature {
    #[classattr]
    pub const LENGTH: usize = 65;

    #[new]
    pub fn new(sig_bytes: [u8; Self::LENGTH]) -> Self {
        near_crypto::Secp256K1Signature::from(sig_bytes).into()
    }

    /// Create an empty signature.
    ///
    /// Returns:
    ///     Secp256K1Signature
    #[staticmethod]
    pub fn empty() -> Self {
        unwrap_enum!(
            near_crypto::Signature::empty(near_crypto::KeyType::SECP256K1),
            near_crypto::Signature::SECP256K1
        )
    }

    /// Verifies that this signature comes from signing the data with given public key.
    /// Also if public key isn't on the curve returns `false`.
    ///
    /// Args:
    ///     data (Sequence[int] | bytes): the unsigned message.
    ///     public_key (Secp256K1PublicKey): The public key of the signer.
    ///
    /// Returns:
    ///     bool: Signature verification result
    ///
    pub fn verify(&self, data: &[u8], public_key: &Secp256K1PublicKey) -> bool {
        let pubkey = near_crypto::PublicKey::from(public_key);
        near_crypto::Signature::from(self).verify(data, &pubkey)
    }

    /// Args:
    ///     reject_upper: bool
    ///
    /// Returns:
    ///     bool
    pub fn check_signature_values(&self, reject_upper: bool) -> bool {
        self.0.check_signature_values(reject_upper)
    }

    /// Recover the pubkey of the given message's signer.
    ///
    /// Args:
    ///     msg (bytes | Sequence[int]): the unsigned message.
    ///
    /// Returns:
    ///     Secp256K1PublicKey: The signer's pubkey.
    ///
    pub fn recover(&self, msg: [u8; 32]) -> PyResult<Secp256K1PublicKey> {
        handle_py_err(self.0.recover(msg))
    }

    /// Parse from a string.
    ///
    /// s (str): The string to parse
    ///
    /// Returns:
    ///    Secp256K1Signature
    #[staticmethod]
    #[pyo3(name = "from_str")]
    pub fn new_from_str(s: &str) -> PyResult<Self> {
        Self::from_str(s)
    }
}

#[pyclass(module = "pyonear.crypto", subclass)]
pub struct EmptySigner(pub near_crypto::EmptySigner);

#[pymethods]
impl EmptySigner {
    /// Returns an empty public key.
    ///
    /// Returns:
    ///     ED25519PublicKey: empty pubkey.
    ///
    #[staticmethod]
    pub fn public_key() -> ED25519PublicKey {
        unwrap_enum!(
            near_crypto::EmptySigner {}.public_key(),
            near_crypto::PublicKey::ED25519
        )
    }

    /// Returns an empty signature.
    ///
    /// Returns:
    ///     ED25519Signature: empty signature.
    ///
    #[staticmethod]
    pub fn sign() -> ED25519Signature {
        unwrap_enum!(
            near_crypto::EmptySigner {}.sign(&[]),
            near_crypto::Signature::ED25519
        )
    }

    /// Verifies that this signature comes from signing the data with this signer's public key.
    /// Also if public key isn't on the curve returns `false`.
    ///
    /// Args:
    ///     data (Sequence[int] | bytes): the unsigned message.
    ///     signature (Signature): The signature.
    ///
    /// Returns:
    ///     bool: Signature verification result
    ///
    #[staticmethod]
    pub fn verify(data: &[u8], signature: Signature) -> bool {
        near_crypto::EmptySigner {}.verify(data, &signature.into())
    }
}

impl Clone for EmptySigner {
    fn clone(&self) -> Self {
        Self(near_crypto::EmptySigner {})
    }
}

impl PartialEq for EmptySigner {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

#[pyclass(module = "pyonear.crypto")]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyType {
    ED25519,
    SECP256K1,
}

#[pymethods]
#[pyhash]
impl KeyType {}

impl PyHash for KeyType {}

impl From<KeyType> for near_crypto::KeyType {
    fn from(k: KeyType) -> Self {
        match k {
            KeyType::ED25519 => Self::ED25519,
            KeyType::SECP256K1 => Self::SECP256K1,
        }
    }
}

impl From<near_crypto::KeyType> for KeyType {
    fn from(k: near_crypto::KeyType) -> Self {
        match k {
            near_crypto::KeyType::ED25519 => Self::ED25519,
            near_crypto::KeyType::SECP256K1 => Self::SECP256K1,
        }
    }
}

#[pyclass(module = "pyonear.crypto", subclass)]
#[derive(Clone, PartialEq, From, Into, Serialize, Deserialize)]
pub struct InMemorySigner(pub near_crypto::InMemorySigner);
common_methods_default!(InMemorySigner);

impl Debug for InMemorySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemorySigner")
            .field("account_id", &self.0.account_id)
            .field("public_key", &self.0.public_key)
            .field("secret_key", &self.0.secret_key)
            .finish()
    }
}
impl Display for InMemorySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl RichcmpEqualityOnly for InMemorySigner {}

pybytes_general_via_bincode!(InMemorySigner);
py_from_bytes_general_via_bincode!(InMemorySigner);

#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl InMemorySigner {
    #[new]
    pub fn new(account_id: AccountId, public_key: PublicKey, secret_key: SecretKey) -> Self {
        near_crypto::InMemorySigner {
            account_id: account_id.into(),
            public_key: public_key.into(),
            secret_key: secret_key.into(),
        }
        .into()
    }

    /// Build from seed.
    ///
    /// Args:
    ///     account_id(AccountId): the signer's account ID.
    ///     key_type (KeyType)
    ///     seed (str)
    ///
    /// Returns:
    ///     InMemorySigner
    #[staticmethod]
    pub fn from_seed(account_id: AccountId, key_type: KeyType, seed: &str) -> Self {
        near_crypto::InMemorySigner::from_seed(account_id.into(), key_type.into(), seed).into()
    }

    /// Build the signer from a secret key.
    ///
    /// Args:
    ///     account_id(AccountId): The signer's account ID.
    ///     secret_key (SecretKey): The signer's secret key.
    #[staticmethod]
    pub fn from_secret_key(account_id: AccountId, secret_key: SecretKey) -> Self {
        near_crypto::InMemorySigner::from_secret_key(account_id.into(), secret_key.into()).into()
    }

    /// Read the signer from a file.
    ///
    /// Args:
    ///     path (pathlib.Path): The file to read.
    ///
    /// Returns:
    ///     InMemorySigner
    #[staticmethod]
    pub fn from_file(path: PathBuf) -> PyResult<Self> {
        let underlying = near_crypto::InMemorySigner::from_file(path.as_ref())
            .map_err(|e| PyIOError::new_err(e.to_string()))?;
        Ok(underlying.into())
    }

    /// Randomly generate the key.
    ///
    /// Returns:
    ///     InMemorySigner
    #[staticmethod]
    pub fn from_random(account_id: AccountId, key_type: KeyType) -> Self {
        near_crypto::InMemorySigner::from_random(account_id.into(), key_type.into()).into()
    }

    /// Sign a message with this signer's secret key.
    ///
    /// Args:
    ///     data (bytes | Sequence[int]): The message to sign.
    ///
    /// Returns
    ///     Signature: the message signature.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.0.sign(data).into()
    }

    /// See https://docs.rs/near-crypto/latest/near_crypto/trait.Signer.html#tymethod.compute_vrf_with_proof
    ///
    /// Args:
    ///     data (bytes | Sequence[int])
    ///
    /// Returns:
    ///     tuple[list[int], list[int]]
    ///
    pub fn compute_vrf_with_proof(&self, data: &[u8]) -> ([u8; 32], [u8; 64]) {
        let res = self.0.compute_vrf_with_proof(data);
        (res.0 .0, res.1 .0)
    }

    /// Save to a file.
    ///
    /// Args:
    ///     path (pathlib.Path)
    ///
    /// Returns:
    ///     None
    ///
    pub fn write_to_file(&self, path: PathBuf) -> PyResult<()> {
        self.0
            .write_to_file(path.as_ref())
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Verifies that this signature comes from signing the data with this signer's public key.
    /// Also if public key isn't on the curve returns `false`.
    ///
    /// Args:
    ///     data (Sequence[int] | bytes): the unsigned message.
    ///     signature (Signature): The signature.
    ///
    /// Returns:
    ///     bool: Signature verification result
    ///
    pub fn verify(&self, data: &[u8], signature: Signature) -> bool {
        self.0.verify(data, &signature.into())
    }

    /// AccountId: the signer's account ID.
    #[getter]
    pub fn account_id(&self) -> AccountId {
        self.0.account_id.clone().into()
    }
    /// PublicKey: the signer's public key.
    #[getter]
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key.clone().into()
    }

    /// SecretKey: the signer's secret key.
    #[getter]
    pub fn secret_key(&self) -> SecretKey {
        self.0.secret_key.clone().into()
    }
}

/// A file for storing keys in.
#[pyclass(module = "pyonear.crypto", subclass)]
#[derive(From, Into, Serialize, Deserialize)]
pub struct KeyFile(pub near_crypto::KeyFile);
impl Clone for KeyFile {
    fn clone(&self) -> Self {
        let underlying = &self.0;
        near_crypto::KeyFile {
            account_id: underlying.account_id.clone(),
            public_key: underlying.public_key.clone(),
            secret_key: underlying.secret_key.clone(),
        }
        .into()
    }
}
impl PartialEq for KeyFile {
    fn eq(&self, other: &Self) -> bool {
        let underlying = &self.0;
        let other_underlying = &other.0;
        underlying.account_id == other_underlying.account_id
            && underlying.public_key == other_underlying.public_key
            && underlying.secret_key == other_underlying.secret_key
    }
}
common_methods_default!(KeyFile);

impl Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyFile")
            .field("account_id", &self.0.account_id)
            .field("public_key", &self.0.public_key)
            .field("secret_key", &self.0.secret_key)
            .finish()
    }
}
impl Display for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl RichcmpEqualityOnly for KeyFile {}

pybytes_general_via_bincode!(KeyFile);
py_from_bytes_general_via_bincode!(KeyFile);

#[richcmp_eq_only]
#[common_methods]
#[pymethods]
impl KeyFile {
    #[new]
    pub fn new(account_id: AccountId, public_key: PublicKey, secret_key: SecretKey) -> Self {
        near_crypto::KeyFile {
            account_id: account_id.into(),
            public_key: public_key.into(),
            secret_key: secret_key.into(),
        }
        .into()
    }

    /// Read from a file.
    ///
    /// Args:
    ///     path (pathlib.Path): The file to read.
    ///
    /// Returns:
    ///     KeyFile
    #[staticmethod]
    pub fn from_file(path: PathBuf) -> PyResult<Self> {
        let underlying = near_crypto::KeyFile::from_file(path.as_ref())
            .map_err(|e| PyIOError::new_err(e.to_string()))?;
        Ok(underlying.into())
    }

    /// Write to a file.
    ///
    /// Args:
    ///     path (pathlib.Path): The file to write.
    ///
    pub fn write_to_file(&self, path: PathBuf) -> PyResult<()> {
        self.0
            .write_to_file(path.as_ref())
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// AccountId: the account ID.
    #[getter]
    pub fn account_id(&self) -> AccountId {
        self.0.account_id.clone().into()
    }
    /// PublicKey: the public key.
    #[getter]
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key.clone().into()
    }
    /// SecretKey: the secret key.
    #[getter]
    pub fn secret_key(&self) -> SecretKey {
        self.0.secret_key.clone().into()
    }
}

#[derive(Clone, PartialEq, From, FromPyObject, EnumIntoPy)]
pub enum Signer {
    InMemory(InMemorySigner),
    Empty(EmptySigner),
}

pub(crate) fn create_crypto_mod(py: Python<'_>) -> PyResult<&PyModule> {
    let m = PyModule::new(py, "crypto")?;
    add_classes!(
        m,
        ED25519PublicKey,
        Secp256K1PublicKey,
        ED25519SecretKey,
        Secp256K1SecretKey,
        ED25519Signature,
        Secp256K1Signature,
        EmptySigner,
        InMemorySigner,
        KeyType,
        KeyFile,
        ED25519SecretKey,
        Secp256K1SecretKey,
        ED25519Signature,
        Secp256K1Signature,
        EmptySigner,
        InMemorySigner,
        KeyType,
        KeyFile
    );
    add_union!("PublicKey", m, py, ED25519PublicKey, Secp256K1PublicKey)?;
    add_union!("SecretKey", m, py, ED25519SecretKey, Secp256K1SecretKey)?;
    add_union!("Signature", m, py, ED25519Signature, Secp256K1Signature)?;
    add_union!("Signer", m, py, InMemorySigner, EmptySigner)?;
    Ok(m)
}
