// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
pub use local_agent_rs as la;
use pyo3::prelude::*;

#[pyclass]
#[derive(Clone, Debug)]
#[allow(non_camel_case_types)]
pub enum ReasonCode {
    UNKNOWN,
    GUEST_SESSION,
    RESTRICTED_SERVER,
    BAD_CERT_SIGNATURE,
    CERT_NOT_PROVIDED,
    CERTIFICATE_EXPIRED,
    CERTIFICATE_REVOKED,
    MAX_SESSIONS_UNKNOWN,
    MAX_SESSIONS_FREE,
    MAX_SESSIONS_BASIC,
    MAX_SESSIONS_PLUS,
    MAX_SESSIONS_VISIONARY,
    MAX_SESSIONS_PRO,
    KEY_USED_MULTIPLE_TIMES,
    SERVER_ERROR,
    POLICY_VIOLATION_LOW_PLAN,
    POLICY_VIOLATION_DELINQUENT,
    USER_TORRENT_NOT_ALLOWED,
    USER_BAD_BEHAVIOR,
}

impl From<i32> for ReasonCode {
    fn from(reason: i32) -> Self {
        match reason {
            la::REASON_CODE_UNKNOWN => ReasonCode::UNKNOWN,
            la::REASON_CODE_GUEST_SESSION => ReasonCode::GUEST_SESSION,
            la::REASON_CODE_RESTRICTED_SERVER => ReasonCode::RESTRICTED_SERVER,
            la::REASON_CODE_BAD_CERT_SIGNATURE => {
                ReasonCode::BAD_CERT_SIGNATURE
            }
            la::REASON_CODE_CERT_NOT_PROVIDED => ReasonCode::CERT_NOT_PROVIDED,
            la::REASON_CODE_CERTIFICATE_EXPIRED => {
                ReasonCode::CERTIFICATE_EXPIRED
            }
            la::REASON_CODE_CERTIFICATE_REVOKED => {
                ReasonCode::CERTIFICATE_REVOKED
            }
            la::REASON_CODE_MAX_SESSIONS_UNKNOWN => {
                ReasonCode::MAX_SESSIONS_UNKNOWN
            }
            la::REASON_CODE_MAX_SESSIONS_FREE => ReasonCode::MAX_SESSIONS_FREE,
            la::REASON_CODE_MAX_SESSIONS_BASIC => {
                ReasonCode::MAX_SESSIONS_BASIC
            }
            la::REASON_CODE_MAX_SESSIONS_PLUS => ReasonCode::MAX_SESSIONS_PLUS,
            la::REASON_CODE_MAX_SESSIONS_VISIONARY => {
                ReasonCode::MAX_SESSIONS_VISIONARY
            }
            la::REASON_CODE_MAX_SESSIONS_PRO => ReasonCode::MAX_SESSIONS_PRO,
            la::REASON_CODE_KEY_USED_MULTIPLE_TIMES => {
                ReasonCode::KEY_USED_MULTIPLE_TIMES
            }
            la::REASON_CODE_SERVER_ERROR => ReasonCode::SERVER_ERROR,
            la::REASON_CODE_POLICY_VIOLATION_LOW_PLAN => {
                ReasonCode::POLICY_VIOLATION_LOW_PLAN
            }
            la::REASON_CODE_POLICY_VIOLATION_DELINQUENT => {
                ReasonCode::POLICY_VIOLATION_DELINQUENT
            }
            la::REASON_CODE_USER_TORRENT_NOT_ALLOWED => {
                ReasonCode::USER_TORRENT_NOT_ALLOWED
            }
            la::REASON_CODE_USER_BAD_BEHAVIOR => ReasonCode::USER_BAD_BEHAVIOR,
            _ => ReasonCode::UNKNOWN,
        }
    }
}

#[pyclass(get_all)]
#[derive(Clone, Debug)]
pub struct Reason {
    pub code: ReasonCode,
    pub is_final: bool,
    pub description: String,
}

#[pymethods]
impl Reason {
    /// This method is used to convert the object to a string for easier
    /// debugging in Python.
    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{:?}", self))
    }
}

impl From<la::Reason> for Reason {
    fn from(reason: la::Reason) -> Self {
        Reason {
            code: ReasonCode::from(reason.code),
            is_final: reason.is_final,
            description: reason.description,
        }
    }
}
