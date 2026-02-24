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
use super::{Request, Response, Result};
use async_trait::async_trait;

/// Represents a transport layer, such as a TCP stream or a Unix domain socket,
/// or a file.

#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, request: Request) -> Result<()>;
    async fn recv(&self) -> Result<Response>;
    async fn close(&self) -> Result<()>;
}
