// -----------------------------------------------------------------------------
// Copyright (c) 2026 Proton AG
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
//! Errors reported by the kill switch.

/// Errors that can occur while enabling or disabling the kill switch.
///
/// The netlink variants all wrap an [`std::io::Error`] but are kept apart so
/// callers can tell *where* the exchange with netfilter broke down: failing to
/// open the socket usually means the process lacks `CAP_NET_ADMIN`, whereas a
/// rejected batch points at an unsupported kernel or a malformed rule.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to open the netfilter netlink socket: {0}")]
    NetlinkOpen(#[source] std::io::Error),

    #[error("failed to send the rule batch to netfilter: {0}")]
    NetlinkSend(#[source] std::io::Error),

    #[error("failed to receive the netfilter response: {0}")]
    NetlinkReceive(#[source] std::io::Error),

    #[error("netfilter rejected the rule batch: {0}")]
    NetlinkRejected(#[source] std::io::Error),

    #[error("invalid interface name {0:?}: it must be non-empty and free of NUL bytes")]
    InvalidInterfaceName(String),

    #[error("invalid fwmark {0:?}: {1}")]
    InvalidFwmark(String, #[source] std::num::ParseIntError),

    #[error("invalid server IP {0:?}: {1}")]
    InvalidServerIp(String, #[source] std::net::AddrParseError),

    #[error("runtime error {0}")]
    Runtime(#[source] tokio::task::JoinError),
}

pub type Result<T> = std::result::Result<T, Error>;
