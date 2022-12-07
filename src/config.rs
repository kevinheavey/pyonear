use near_primitives_core::config::{
    ActionCosts as ActionCostsOriginal, ExtCosts as ExtCostsOriginal,
};
use pyo3::prelude::*;
use solders_macros::enum_original_mapping;

use crate::hash_enum;

/// Strongly-typed representation of the fees for counting.
#[pyclass(module = "pyonear.config")]
#[derive(Copy, Clone, Hash, PartialEq, Eq, Debug, PartialOrd, Ord)]
#[enum_original_mapping(ExtCostsOriginal)]
#[allow(non_camel_case_types)]
pub enum ExtCosts {
    base,
    contract_loading_base,
    contract_loading_bytes,
    read_memory_base,
    read_memory_byte,
    write_memory_base,
    write_memory_byte,
    read_register_base,
    read_register_byte,
    write_register_base,
    write_register_byte,
    utf8_decoding_base,
    utf8_decoding_byte,
    utf16_decoding_base,
    utf16_decoding_byte,
    sha256_base,
    sha256_byte,
    keccak256_base,
    keccak256_byte,
    keccak512_base,
    keccak512_byte,
    ripemd160_base,
    ripemd160_block,
    ed25519_verify_base,
    ed25519_verify_byte,
    ecrecover_base,
    log_base,
    log_byte,
    storage_write_base,
    storage_write_key_byte,
    storage_write_value_byte,
    storage_write_evicted_byte,
    storage_read_base,
    storage_read_key_byte,
    storage_read_value_byte,
    storage_remove_base,
    storage_remove_key_byte,
    storage_remove_ret_value_byte,
    storage_has_key_base,
    storage_has_key_byte,
    storage_iter_create_prefix_base,
    storage_iter_create_prefix_byte,
    storage_iter_create_range_base,
    storage_iter_create_from_byte,
    storage_iter_create_to_byte,
    storage_iter_next_base,
    storage_iter_next_key_byte,
    storage_iter_next_value_byte,
    touching_trie_node,
    read_cached_trie_node,
    promise_and_base,
    promise_and_per_promise,
    promise_return,
    validator_stake_base,
    validator_total_stake_base,
    alt_bn128_g1_multiexp_base,
    alt_bn128_g1_multiexp_element,
    alt_bn128_pairing_check_base,
    alt_bn128_pairing_check_element,
    alt_bn128_g1_sum_base,
    alt_bn128_g1_sum_element,
}
hash_enum!(ExtCosts);

// Type of an action, used in fees logic.
#[pyclass(module = "pyonear.config")]
#[derive(Copy, Clone, Hash, PartialEq, Eq, Debug, PartialOrd, Ord)]
#[enum_original_mapping(ActionCostsOriginal)]
#[allow(non_camel_case_types)]
pub enum ActionCosts {
    create_account,
    delete_account,
    deploy_contract,
    function_call,
    transfer,
    stake,
    add_key,
    delete_key,
    value_return,
    new_receipt,
}
hash_enum!(ActionCosts);

pub(crate) fn create_config_mod(py: Python<'_>) -> PyResult<&PyModule> {
    let m = PyModule::new(py, "config")?;
    m.add_class::<ActionCosts>()?;
    m.add_class::<ExtCosts>()?;
    Ok(m)
}
