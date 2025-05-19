// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
pub use procure::{Load, Server, UserLocation};

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
    user_location: UserLocation,
}

impl ServerStatus {
    pub fn new(status_id: &str,
               servers: Vec<Server>,
               user_location : UserLocation) -> Self {
        Self { status_id : status_id.to_string(),
               servers,
               user_location,
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
            &self.user_location,
            &mut loads,
            &self.servers,
            status_file,
        )?;

        Ok(loads)
    }

    pub fn read_status(
        status_file: &[u8],
    ) -> Result<procure::Status> {
        Ok(procure::Status::try_from(status_file)?)
    }
}
