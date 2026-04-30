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

use super::parameters::PcapFileInfo;
use super::command_wire::CommandWire;

#[derive(
    serde::Deserialize, serde::Serialize, Debug, clap::Parser, Clone,
    zvariant::Type,
)]
#[cfg_attr(feature = "python", pyo3::pyclass(new = "from_fields"))]
pub struct PcapStop;

#[cfg_attr(feature = "python", pyo3::pyclass(new = "from_fields"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, clap::Args, zvariant::Type)]
pub struct PcapStart {
    #[clap(flatten)]
    pub file_info: PcapFileInfo,
    #[clap(long, default_value_t = 0)]
    pub max_bytes: u64,
}

/// Commands that can be sent to the protun service.
///
/// Wire format: `(uv)` — a struct containing a u32 discriminant and a variant payload.
/// disc=0 → PcapStart payload, disc=1 → PcapStop (payload ignored).
#[derive(Debug, Clone, clap::Subcommand, zvariant::Type)]
#[zvariant(signature = "(uv)")]
#[cfg_attr(feature = "python", pyo3::pyclass)]
pub enum Command {
    PcapStart(PcapStart),
    PcapStop(PcapStop),
}

impl serde::Serialize for Command {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        CommandWire::try_from(self)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Command {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        CommandWire::deserialize(deserializer)
            .and_then(|w| Command::try_from(w).map_err(serde::de::Error::custom))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::parameters::{FileWriteMode, PcapFileInfo, SharedFd};

    fn roundtrip(cmd: &Command) -> Command {
        let ctx = zvariant::serialized::Context::new_dbus(zvariant::LE, 0);
        let data = zvariant::to_bytes(ctx, cmd).expect("serialization failed");
        let (result, _): (Command, _) = data.deserialize().expect("deserialization failed");
        result
    }

    #[test]
    fn pcap_stop_roundtrips() {
        let result = roundtrip(&Command::PcapStop(PcapStop));
        assert!(matches!(result, Command::PcapStop(_)));
    }

    #[test]
    fn pcap_start_roundtrips() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let std_fd: std::os::fd::OwnedFd = file.into();
        let cmd = Command::PcapStart(PcapStart {
            file_info: PcapFileInfo {
                fd: SharedFd(std_fd.into()),
                mode: FileWriteMode::Overwrite,
            },
            max_bytes: 4096,
        });
        let result = roundtrip(&cmd);
        match result {
            Command::PcapStart(start) => {
                assert_eq!(start.max_bytes, 4096);
                assert_eq!(start.file_info.mode, FileWriteMode::Overwrite);
            }
            _ => panic!("expected PcapStart"),
        }
    }
}
