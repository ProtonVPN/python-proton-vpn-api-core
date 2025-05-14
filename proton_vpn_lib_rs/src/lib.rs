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
    user_position: [f32; 2],
    user_country: String,
}

impl ServerStatus {
    pub fn new(status_id: &str,
               servers: Vec<Server>,
               user_position : [f32; 2],
               user_country: &str) -> Self {
        Self { status_id : status_id.to_string(),
               servers,
               user_position,
               user_country: user_country.to_string()
            }
    }

    pub fn status_id(&self) -> &str {
        &self.status_id
    }

    pub fn compute_loads(
        &self,
        status_file: &[u8],
    ) -> Result<Vec<Load>> {
        let mut loads = Vec::new();
        loads.resize(self.servers.len(), Load::default());

        procure::compute_loads(
            &self.user_position,
            &self.user_country,
            &mut loads,
            &self.servers,
            status_file,
        )?;

        Ok(loads)
    }
}
