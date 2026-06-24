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
//! Represents the reason for a status message.

/// The reason code is used to indicate why a connection is jailed.
pub const REASON_CODE_GUEST_SESSION: i32 = 86100;
pub const REASON_CODE_RESTRICTED_SERVER: i32 = 86104;
pub const REASON_CODE_BAD_CERT_SIGNATURE: i32 = 86105;
pub const REASON_CODE_CERT_NOT_PROVIDED: i32 = 86106;
pub const REASON_CODE_CERTIFICATE_EXPIRED: i32 = 86101;
pub const REASON_CODE_CERTIFICATE_REVOKED: i32 = 86102;
pub const REASON_CODE_MAX_SESSIONS_UNKNOWN: i32 = 86110;
pub const REASON_CODE_MAX_SESSIONS_FREE: i32 = 86111;
pub const REASON_CODE_MAX_SESSIONS_BASIC: i32 = 86112;
pub const REASON_CODE_MAX_SESSIONS_PLUS: i32 = 86113;
pub const REASON_CODE_MAX_SESSIONS_VISIONARY: i32 = 86114;
pub const REASON_CODE_MAX_SESSIONS_PRO: i32 = 86115;
pub const REASON_CODE_KEY_USED_MULTIPLE_TIMES: i32 = 86103;
pub const REASON_CODE_SERVER_ERROR: i32 = 86150;
pub const REASON_CODE_POLICY_VIOLATION_LOW_PLAN: i32 = 86151;
pub const REASON_CODE_POLICY_VIOLATION_DELINQUENT: i32 = 86152;
pub const REASON_CODE_USER_TORRENT_NOT_ALLOWED: i32 = 86153;
pub const REASON_CODE_USER_BAD_BEHAVIOR: i32 = 86154;
pub const REASON_CODE_TWOFA_UNSPECIFIED: i32 = 86120; // 2FA necessary, reason not specified
pub const REASON_CODE_TWOFA_EXPIRED: i32 = 86121; // 2FA necessary, session expired
pub const REASON_CODE_TWOFA_SITUATION_CHANGED: i32 = 86122; // 2FA necessary, situation changed (e.g. new connection, change of location)

#[cfg_attr(feature = "python", pyo3::pyclass(eq, eq_int, rename_all = "SCREAMING_SNAKE_CASE"))]
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[allow(non_camel_case_types)]
#[repr(i32)]
pub enum ReasonCode {
    Unknown,
    GuestSession,
    RestrictedServer,
    BadCertSignature,
    CertNotProvided,
    CertificateExpired,
    CertificateRevoked,
    MaxSessionsUnknown,
    MaxSessionsFree,
    MaxSessionsBasic,
    MaxSessionsPlus,
    MaxSessionsVisionary,
    MaxSessionsPro,
    KeyUsedMultipleTimes,
    ServerError,
    PolicyViolationLowPlan,
    PolicyViolationDelinquent,
    UserTorrentNotAllowed,
    UserBadBehavior,
    TwofaUnspecified,
    TwofaExpired,
    TwofaSituationChanged,
}

impl From<i32> for ReasonCode {
    fn from(reason: i32) -> Self {
        match reason {
            REASON_CODE_GUEST_SESSION => ReasonCode::GuestSession,
            REASON_CODE_RESTRICTED_SERVER => ReasonCode::RestrictedServer,
            REASON_CODE_BAD_CERT_SIGNATURE => ReasonCode::BadCertSignature,
            REASON_CODE_CERT_NOT_PROVIDED => ReasonCode::CertNotProvided,
            REASON_CODE_CERTIFICATE_EXPIRED => ReasonCode::CertificateExpired,
            REASON_CODE_CERTIFICATE_REVOKED => ReasonCode::CertificateRevoked,
            REASON_CODE_MAX_SESSIONS_UNKNOWN => ReasonCode::MaxSessionsUnknown,
            REASON_CODE_MAX_SESSIONS_FREE => ReasonCode::MaxSessionsFree,
            REASON_CODE_MAX_SESSIONS_BASIC => ReasonCode::MaxSessionsBasic,
            REASON_CODE_MAX_SESSIONS_PLUS => ReasonCode::MaxSessionsPlus,
            REASON_CODE_MAX_SESSIONS_VISIONARY => ReasonCode::MaxSessionsVisionary,
            REASON_CODE_MAX_SESSIONS_PRO => ReasonCode::MaxSessionsPro,
            REASON_CODE_KEY_USED_MULTIPLE_TIMES => ReasonCode::KeyUsedMultipleTimes,
            REASON_CODE_SERVER_ERROR => ReasonCode::ServerError,
            REASON_CODE_POLICY_VIOLATION_LOW_PLAN => ReasonCode::PolicyViolationLowPlan,
            REASON_CODE_POLICY_VIOLATION_DELINQUENT => ReasonCode::PolicyViolationDelinquent,
            REASON_CODE_USER_TORRENT_NOT_ALLOWED => ReasonCode::UserTorrentNotAllowed,
            REASON_CODE_USER_BAD_BEHAVIOR => ReasonCode::UserBadBehavior,
            REASON_CODE_TWOFA_UNSPECIFIED => ReasonCode::TwofaUnspecified,
            REASON_CODE_TWOFA_EXPIRED => ReasonCode::TwofaExpired,
            REASON_CODE_TWOFA_SITUATION_CHANGED => ReasonCode::TwofaSituationChanged,
            _ => ReasonCode::Unknown
        }
    }
}

impl<'de> serde::Deserialize<'de> for ReasonCode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(ReasonCode::from(i32::deserialize(deserializer)?))
    }
}