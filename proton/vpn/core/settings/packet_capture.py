"""The data class for managing packet capture settings.


Copyright (c) 2025 Proton AG

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
from __future__ import annotations

from enum import Enum
from dataclasses import dataclass
import tempfile


class PacketCaptureMode(Enum):
    """Enum for packet capture mode.
    """
    APPEND = "append"
    OVERWRITE = "overwrite"


DEFAULT_DIRECTORY_PATH = tempfile.gettempdir()
DEFAULT_MODE = PacketCaptureMode.OVERWRITE
MAX_PACKET_CAPTURE_FILE_SIZE = 1024 * 1024 * 512  # 0.5 GB


@dataclass
class PacketCapture:
    """
    Class for managing packet capture settings.
    """
    directory_path: str = DEFAULT_DIRECTORY_PATH

    @staticmethod
    def default() -> PacketCapture:  # pylint: disable=unused-argument
        """Creates and returns `PacketCapture` from default configurations."""
        return PacketCapture()

    @property
    def mode(self) -> PacketCaptureMode:
        """Returns the packet capture mode."""
        return DEFAULT_MODE

    @property
    def max_bytes(self) -> int:
        """Returns the maximum file size for packet capture."""
        return MAX_PACKET_CAPTURE_FILE_SIZE
