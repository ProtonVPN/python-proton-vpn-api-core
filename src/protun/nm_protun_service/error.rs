// -----------------------------------------------------------------------------
// Copyright (c) 2025 Proton AG
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
//! Error types for VPN operations.

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    IO(#[from] std::io::Error),
    #[error("{0}")]
    Serini(#[from] serini::Error),
    #[error("{0}")]
    Base64(#[from] base64::DecodeError),
    #[error("{0}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error("{0}")]
    InvalidState(String),
    #[error("Missing setting: {0}")]
    MissingSetting(String),
    #[error("{0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("{0}")]
    AddrParseError(#[from] std::net::AddrParseError),
    #[error("{0}")]
    NetlinkError(#[from] rtnetlink::Error),
    #[error("{0}")]
    ValueError(String),
    #[error("{0}")]
    JsonError(#[from] serde_json::Error),
    #[error("{0}")]
    Infallible(#[from] std::convert::Infallible),
    #[error("{0}")]
    NetLink(String),
    #[error("{0}")]
    SocketFdInvalid(&'static str)
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for zbus::fdo::Error {
    fn from(err: Error) -> Self {
        zbus::fdo::Error::Failed(format!("{}", err))
    }
}
