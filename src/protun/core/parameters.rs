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

use std::path::{Path, PathBuf};
use std::fs::File;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use zvariant::OwnedFd;

/// Newtype around `zvariant::OwnedFd` that implements `Clone` via `dup(2)`.
/// Each clone owns an independent fd; the OS closes the underlying file
/// description when the last fd is closed.
#[derive(Debug)]
pub struct SharedFd(pub OwnedFd);

impl Clone for SharedFd {
    fn clone(&self) -> Self {
        let fd = unsafe { libc::dup(self.0.as_raw_fd()) }; // nosemgrep
        assert!(fd >= 0, "dup failed: {}", std::io::Error::last_os_error());
        // zvariant::OwnedFd accepts From<std::os::fd::OwnedFd>
        SharedFd(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }.into()) // nosemgrep
    }
}

impl serde::Serialize for SharedFd {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for SharedFd {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(SharedFd(OwnedFd::deserialize(d)?))
    }
}

impl zvariant::Type for SharedFd {
    const SIGNATURE: &'static zvariant::Signature = <OwnedFd as zvariant::Type>::SIGNATURE;
}

/// Fd-based pcap file info passed over D-Bus. The caller opens the file and
/// passes the fd; the service never touches the path.
#[cfg_attr(feature = "python", pyo3::pyclass)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct PcapFileInfo {
    pub fd: SharedFd,
    pub mode: FileWriteMode,
}

impl PcapFileInfo {
    pub fn from_path(path: &Path, mode: FileWriteMode) -> Result<Self, std::io::Error> {
        let owned_fd: OwnedFd = {
            let std_fd: std::os::fd::OwnedFd = File::options()
                .create(true)
                .write(true)
                .append(matches!(mode, FileWriteMode::Append))
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?
                .into();
            std_fd.into()
        };
        Ok(Self { fd: SharedFd(owned_fd), mode })
    }
}

impl clap::Args for PcapFileInfo {
    fn augment_args(cmd: clap::Command) -> clap::Command {
        cmd
            .arg(clap::Arg::new("file-path").long("file-path").required(true))
            .arg(clap::Arg::new("mode").long("mode").default_value("overwrite"))
    }
    fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
        Self::augment_args(cmd)
    }
}

impl clap::FromArgMatches for PcapFileInfo {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        let path: PathBuf = matches
            .get_one::<String>("file-path")
            .ok_or_else(|| clap::Error::raw(
                clap::error::ErrorKind::MissingRequiredArgument,
                "--file-path required",
            ))?
            .into();
        let mode = match matches.get_one::<String>("mode").map(|s| s.as_str()) {
            Some("append") => FileWriteMode::Append,
            _ => FileWriteMode::Overwrite,
        };
        Self::from_path(&path, mode)
            .map_err(|e| clap::Error::raw(
                clap::error::ErrorKind::Io,
                e.to_string(),
            ))
    }
    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl PcapFileInfo {
    #[staticmethod]
    #[pyo3(name = "from_path")]
    fn py_from_path(path: &str, mode: FileWriteMode) -> pyo3::PyResult<Self> {
        PcapFileInfo::from_path(Path::new(path), mode)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, clap::ValueEnum, zvariant::Type)]
#[cfg_attr(feature = "python", pyo3::pyclass(eq, eq_int))]
#[serde(rename_all = "kebab-case")]
pub enum FileWriteMode {
    Append,
    Overwrite,
}

/// Peer entry in the vpn.data.peers JSON array
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PeerInfo {
    pub id: String,
    pub endpoint: String,
    pub public_key: String,
    pub udp_ports: Vec<u16>,
    pub tcp_ports: Vec<u16>,
    pub tls_ports: Vec<u16>,
    pub priority: i32,
}
