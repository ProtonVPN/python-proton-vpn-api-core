// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use pyo3::prelude::*;
// -----------------------------------------------------------------------------

fn init_logger() {
    env_logger::init();
}

#[pyclass]
struct Fetcher{}

#[pymodule]
/// This is the entry point for the python module.
fn base(m: &Bound<'_, PyModule>) -> PyResult<()> {

    m.add_class::<Fetcher>()?;

    // Start the logger when the module is returned.
    init_logger();

    Ok(())
}
