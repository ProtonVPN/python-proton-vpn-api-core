// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use crate::{Request, Response, Result};
use async_trait::async_trait;

/// Represents a transport layer, such as a TCP stream or a Unix domain socket,
/// or a file.

#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, request: Request) -> Result<()>;
    async fn recv(&self) -> Result<Response>;
    async fn close(&self) -> Result<()>;
}
