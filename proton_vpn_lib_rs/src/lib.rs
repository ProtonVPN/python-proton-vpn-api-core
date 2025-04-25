// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
pub use procure::Server;

// -----------------------------------------------------------------------------
pub struct ServerStatus
{
    status_id: String,
    servers : Vec<Server>
}

impl ServerStatus {
    pub fn new(status_id: String, servers : Vec::<Server>) -> Self
    {
        Self {
            status_id,
            servers,
        }
    }

    pub fn status_id(&self) -> &str
    {
        &self.status_id
    }
}