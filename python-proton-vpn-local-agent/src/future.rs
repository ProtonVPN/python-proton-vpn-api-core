// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use crate::Result;
use pyo3::IntoPy;

/// Converts a rust future into a python future, making sure to convert errors
/// into Python exceptions.
///
/// This is necessary as async {} blocks in Rust do not have a way to specify
/// their return type.
pub fn future<W, R>(
    py: pyo3::Python,
    work: W,
) -> pyo3::PyResult<pyo3::Bound<pyo3::PyAny>>
where
    W: std::future::Future<Output = Result<R>> + Send + 'static,
    R: IntoPy<pyo3::Py<pyo3::PyAny>>,
{
    pyo3_asyncio_0_21::tokio::future_into_py(py, async move {
        work.await.map_err(pyo3::PyErr::from)
    })
}
