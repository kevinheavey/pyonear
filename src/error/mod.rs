use std::collections::HashMap;

use pyo3::prelude::*;

use self::{core::create_core_mod, exception::create_exception_mod, vm::create_vm_mod};
pub mod core;
pub mod exception;
pub mod vm;

pub(crate) fn create_error_mod(py: Python<'_>) -> PyResult<&PyModule> {
    let error_mod = PyModule::new(py, "error")?;
    let core_mod = create_core_mod(py)?;
    let exception_mod = create_exception_mod(py)?;
    let vm_mod = create_vm_mod(py)?;
    let submodules = [core_mod, exception_mod, vm_mod];
    let modules: HashMap<String, &PyModule> = submodules
        .iter()
        .map(|x| (format!("pyonear.error.{}", x.name().unwrap()), *x))
        .collect();
    let sys_modules = py.import("sys")?.getattr("modules")?;
    sys_modules.call_method1("update", (modules,))?;
    for submod in submodules {
        error_mod.add_submodule(submod)?;
    }
    Ok(error_mod)
}
