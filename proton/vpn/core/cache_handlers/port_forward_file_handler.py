"""
This module contains then logic related to storing forwarded port to file.

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
import os
import pathlib
from proton.vpn.connection import states
from proton.utils.environment import VPNExecutionEnvironment

DEFAULT_FORWARDED_PORT_FILEPATH = os.path.join(
    VPNExecutionEnvironment().path_runtime, "forwarded_port"
)


class PortForwardFileHandler:  # pylint: disable=too-few-public-methods
    """Takes care of file creating/deleting and writing port to file."""

    def __init__(self, filepath: str = DEFAULT_FORWARDED_PORT_FILEPATH):
        self._filepath = pathlib.Path(filepath)

    def on_state_change_update_port(self, state: states.State):
        """Handles the new state.
        If the state is `Connected`, it writes the forwarded port to the file.
        If the state is not `Connected`, it removes the port from the file.

        Args:
            state (State): newly received state object.
        """
        if isinstance(state, states.Connected) and state.forwarded_port:
            self._write_port_to_file(state.forwarded_port)
        elif isinstance(state, (states.Connected, states.Disconnected)):
            self._remove_port_from_file()

    def _write_port_to_file(self, port: int):
        """Writes port to file."""
        with open(self._filepath, mode="w", encoding="utf8") as file:
            file.write(str(port))

    def _remove_port_from_file(self):
        """Removes the port from the file."""
        with open(self._filepath, mode="w", encoding="utf8") as file:
            file.write("")
