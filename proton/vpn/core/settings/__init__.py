"""
This module manages the Proton VPN general settings.


Copyright (c) 2023 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton VPN is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
from proton.vpn.core.settings.settings import Settings, SettingsPersistence
from proton.vpn.core.settings.split_tunneling import SplitTunneling, \
    SplitTunnelingConfig, SplitTunnelingMode
from proton.vpn.core.settings.features import NetShield
from proton.vpn.core.settings.custom_dns import CustomDNSEntry
from proton.vpn.core.settings.packet_capture import PacketCapture, PacketCaptureMode

__all__ = [
    "Settings", "SettingsPersistence", "NetShield",
    "CustomDNSEntry", "SplitTunneling", "SplitTunnelingConfig", "SplitTunnelingMode",
    "PacketCapture", "PacketCaptureMode"
]
