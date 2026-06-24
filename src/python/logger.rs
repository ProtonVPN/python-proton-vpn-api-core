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
use pyo3::prelude::*;
use pyo3::types::PyDict;
// -----------------------------------------------------------------------------
use super::super::error::*;

// Set the rust log level to something sensible but not too verbose,
// let the python logger filter.
const DEFAULT_LOG_LEVEL: log::Level = log::Level::Debug;
const LOG_NAME: &str = "proton.vpn.platform";
const GET_LOGGER: &str = "getLogger";
const LOGGER: &str = "logger";

fn create_new_py_logger() -> String {
    format!(
r#"
import logging

class ProtonVPNLinuxLogger(logging.Logger):
    """
    This logger class is used to inject the rust_info into the log record,
    so that we can use the lineno and name from the rust code.
    """
    def makeRecord(self, name, level, fn, lno, msg, args, exc_info,
                func=None, extra=None, sinfo=None):
        # Make the record
        rv = super().makeRecord(name, level, fn, lno, msg, args, exc_info,
                                func, extra, sinfo)
        # Get the additional rust info
        if extra:
            rust_info = extra.get("rust_info", {{}})

            rv.name = rust_info.get("name", rv.name)       # Overwrite name
            rv.lineno = rust_info.get("lineno", rv.lineno) # Overwrite lineno

        return rv

old_logger_class = logging._loggerClass
logging.setLoggerClass(ProtonVPNLinuxLogger)
try:
    {LOGGER} = {GET_LOGGER}("{LOG_NAME}")
finally:
    logging.setLoggerClass(old_logger_class)
"#
    )
}

/// Logger implementation for the Python logger.
/// This logger is used to log messages from the Rust code to the Python logger.
/// The Python logger is a Python object that has the following methods:
/// - error
/// - warn
/// - info
/// - debug
///
/// The rust logger forwards the log messages to these methods.
struct Logger {
    py_logger: Py<PyAny>,
}

impl Logger {
    /// Creates a new Logger instance.
    pub fn new(py: Python, get_py_logger: Py<PyAny>) -> PyResult<Self> {
        // Add  the getLogger function to the locals
        let locals = PyDict::new(py);
        locals.set_item(GET_LOGGER, get_py_logger)?;

        let c_string = std::ffi::CString::new(create_new_py_logger().as_str())?;
        py.run(&c_string, Some(&locals), None)?;

        let py_logger = locals.get_item(LOGGER)?.ok_or(PyErr::new::<
            pyo3::exceptions::PyException,
            _,
        >(
            "Failed to get logger",
        ))?;

        Ok(Logger {
            py_logger: py_logger.into(),
        })
    }

    pub fn get_py_logger(&self) -> &Py<PyAny> {
        &self.py_logger
    }

    /// Returns the log level as a string mapping to the Python logger method.
    fn get_level(level: log::Level) -> &'static str {
        match level {
            log::Level::Error => "error",
            log::Level::Warn => "warn",
            log::Level::Info => "info",
            log::Level::Debug => "debug",
            log::Level::Trace => "debug",
        }
    }
}

impl log::Log for Logger {
    /// Returns true if the log level is enabled, this logger always returns
    /// true.
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= DEFAULT_LOG_LEVEL
    }

    /// Logs the message to the Python logger.
    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        // Call the Python logger method
        let result = Python::attach(|py| -> PyResult<()> {
            let rust_info = pyo3::types::PyDict::new(py);

            // Add the file and line number if available
            if let Some(file_path) = record.file() {
                if let Some(file) = std::path::Path::new(file_path).file_name()
                {
                    if let Some(filename) = file.to_str() {
                        let filename = filename.to_string();
                        rust_info.set_item(
                            "name",
                            format!("{LOG_NAME}/{}", filename),
                        )?;
                    }
                }
            }
            if let Some(line) = record.line() {
                rust_info.set_item("lineno", line)?;
            }

            let extras = pyo3::types::PyDict::new(py);
            extras.set_item("rust_info", rust_info)?;

            if let Ok(log) = self
                .py_logger
                .bind(py)
                .getattr(Logger::get_level(record.level()))
            {
                let kwargs = pyo3::types::PyDict::new(py);

                kwargs.set_item("extra", extras)?;

                // If the log fails there's nothing much we can do
                let msg = record.args().to_string();
                _ = log.call((msg,), Some(&kwargs));
            }

            Ok(())
        });

        match result {
            Ok(_) => (),
            Err(error) => eprintln!("Failure in logger: {}", error),
        }
    }

    // Flush the logger, this does nothing.
    fn flush(&self) {}
}

/// Initialize the logger for the proton.vpn.platform, this forwards to the
/// python logger.
#[pyfunction]
pub fn init_logger(get_logger: Py<PyAny>) -> PyResult<Py<PyAny>> {
    Python::attach(|py| -> PyResult<Py<PyAny>> {
        // Create a new rust logger instance, this will forward log messages to
        // the python logger.
        let logger = Logger::new(py, get_logger)?;

        // Get a reference to the python logger so it can be configured at
        // the python level.
        let py_logger = logger.get_py_logger().clone_ref(py);

        // We have our own logger implementation which delegates to the python
        // logger. The log module takes a heap allocated object that implements
        // the log::Log trait.
        //
        // The only alternative is to use log::set_logger which requires a
        // `static &log::Log trait object. Making our wrapping logger static is
        // possible but complicates it as it means it has to support being
        // instantiated without the python logger, as that is how it would be
        // initialized.
        log::set_boxed_logger(Box::new(logger))
            .map_err(Error::SetLoggerError)?;

        // Set the rust log level to something sensible but not too verbose,
        // let the python logger filter.
        log::set_max_level(DEFAULT_LOG_LEVEL.to_level_filter());

        Ok(py_logger)
    })
}
