// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
//
// This file is part of ProtonVPN.
//
// ProtonVPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ProtonVPN is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
// -----------------------------------------------------------------------------

/// Converts a rust future into a python future, making sure to convert errors
/// into Python exceptions.
///
/// This is necessary as async {} blocks in Rust do not have a way to specify
/// their return type.
pub fn future<W, R, E>(
    py: pyo3::Python,
    work: W,
) -> pyo3::PyResult<pyo3::Bound<pyo3::PyAny>>
where
    W: std::future::Future<Output = Result<R, E>> + Send + 'static,
    R: for<'py> pyo3::IntoPyObject<'py> + Send + 'static,
    E: std::error::Error + Send + Into<pyo3::PyErr> + 'static,
{
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        work.await.map_err(Into::<pyo3::PyErr>::into)
    })
}

/// Macro to simplify calling the future function.
/// 
/// It can be invoked with a function or a method call and will automatically
/// clone self to allow the future to own it.
/// Example usage:
/// ```
/// await_py!(py, self.some_method(arg1, arg2))
/// await_py!(py, some_function(arg1, arg2))
/// ```
///
/// This significantly reduces the boilerplate when wrapping rust async
/// functions in python.
macro_rules! await_py {
    // Matches a method call
    ($py:ident, $self:ident.$method:ident($($args:expr),*)) => {
        {
            let this = $self.clone();
            future($py, async move {
                this.$method($($args),*).await
            })
        }
    };

    // Matches a function call
    ($py:ident, $func_call:expr) => {
        future($py, async move {
            $func_call.await
        })
    };
}

pub(crate) use await_py;
