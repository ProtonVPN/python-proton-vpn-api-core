"""
Cache Handler module.


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

import json
import os


class CacheHandler:
    """Used to save, load, and remove cache files."""
    def __init__(self, filepath: str):
        self._fp = filepath

    def save(self, newdata: dict):
        """Save data to cache file."""
        with open(self._fp, "w") as f:  # pylint: disable=W1514, C0103
            json.dump(newdata, f, indent=4)  # pylint: disable=C0103

    def load(self):
        """Load data from cache file, if it exists."""
        if not os.path.isfile(self._fp):
            return None

        with open(self._fp, "r") as f:  # pylint: disable=W1514, C0103
            return json.load(f)  # pylint: disable=C0103

    def remove(self):
        """ Remove cache from disk."""
        if os.path.exists(self._fp):
            os.remove(self._fp)
