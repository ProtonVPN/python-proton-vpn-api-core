// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
pub use procure::{Load, Server};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Procure(#[from] procure::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

// -----------------------------------------------------------------------------
pub struct ServerStatus {
    status_id: String,
    servers: Vec<Server>,
}

impl ServerStatus {
    pub fn new(status_id: String, servers: Vec<Server>) -> Self {
        Self { status_id, servers }
    }

    pub fn status_id(&self) -> &str {
        &self.status_id
    }

    pub fn compute_loads(
        &self,
        user_position: &[f32; 2],
        user_country: &str,
        status_file: &[u8],
    ) -> Result<Vec<Load>> {
        let mut loads = Vec::new();
        loads.resize(self.servers.len(), Load::default());

        procure::compute_loads(
            user_position,
            user_country,
            &mut loads,
            &self.servers,
            status_file,
        )?;

        Ok(loads)
    }
}
