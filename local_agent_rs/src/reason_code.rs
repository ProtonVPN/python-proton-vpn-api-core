// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
/// Represents the reason for a status message.

/// The reason code is used to indicate why a connection is jailed.
pub const REASON_CODE_UNKNOWN: i32 = 0;
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
