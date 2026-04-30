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

use zvariant::OwnedValue;
use super::command::{Command, PcapStop};

pub(super) const DISC_PCAP_START: u32 = 0;
pub(super) const DISC_PCAP_STOP: u32 = 1;

// D-Bus variants require a typed payload; use a u8 zero as a placeholder for unit commands.
const EMPTY_PAYLOAD: u8 = 0;

/// Explicit wire type for `Command`. Derives all zvariant/serde machinery automatically.
#[derive(Debug, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub(super) struct CommandWire {
    pub discriminant: u32,
    pub payload: OwnedValue,
}

/// Convert a `Serialize + Type` value to an `OwnedValue` (D-Bus variant wrapping the value).
pub(super) fn to_owned_value<T: serde::Serialize + zvariant::Type>(v: &T) -> zvariant::Result<OwnedValue> {
    let ctx = zvariant::serialized::Context::new_dbus(zvariant::LE, 0);
    let bytes = zvariant::to_bytes(ctx, &zvariant::as_value::Serialize(v))?;
    let (owned, _): (OwnedValue, _) = bytes.deserialize()?;
    Ok(owned)
}

/// Extract a `Deserialize + Type` value from an `OwnedValue` (D-Bus variant).
pub(super) fn from_owned_value<T: for<'de> serde::Deserialize<'de> + zvariant::Type>(
    v: OwnedValue,
) -> zvariant::Result<T> {
    let ctx = zvariant::serialized::Context::new_dbus(zvariant::LE, 0);
    let value = zvariant::Value::from(v);
    let bytes = zvariant::to_bytes(ctx, &value)?;
    let (des, _): (zvariant::as_value::Deserialize<T>, _) = bytes.deserialize()?;
    Ok(des.0)
}

impl TryFrom<&Command> for CommandWire {
    type Error = zvariant::Error;

    fn try_from(c: &Command) -> Result<Self, Self::Error> {
        Ok(match c {
            Command::PcapStart(s) => Self {
                discriminant: DISC_PCAP_START,
                payload: to_owned_value(s)?,
            },
            Command::PcapStop(_) => Self {
                discriminant: DISC_PCAP_STOP,
                payload: to_owned_value(&EMPTY_PAYLOAD)?,
            },
        })
    }
}

impl TryFrom<CommandWire> for Command {
    type Error = zvariant::Error;

    fn try_from(w: CommandWire) -> Result<Self, Self::Error> {
        match w.discriminant {
            DISC_PCAP_START => Ok(Command::PcapStart(from_owned_value(w.payload)?)),
            DISC_PCAP_STOP => Ok(Command::PcapStop(PcapStop)),
            d => Err(zvariant::Error::Message(format!("unknown discriminant {d}"))),
        }
    }
}
