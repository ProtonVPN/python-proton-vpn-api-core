"""
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
from importlib.metadata import version
from packaging.version import Version

fido2_version = Version(version("fido2"))
if fido2_version >= Version("2.0.0"):
    from proton.vpn.session.fido2_2 import (create_client,  # noqa: F401
                                            create_options,
                                            create_from_client_assertion)
elif fido2_version >= Version("1.1.2"):
    from proton.vpn.session.fido2_1 import (create_client,  # noqa: F401
                                            create_options,
                                            create_from_client_assertion)
else:
    raise ImportError(
        f"python3-fido2 version {fido2_version} not supported. "
        "Version 1.1.2 or higher required."
    )

__all__ = [
    "create_client",
    "create_options",
    "create_from_client_assertion"
]
