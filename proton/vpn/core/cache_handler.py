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
from pathlib import Path
from proton.vpn import logging


logger = logging.getLogger(__name__)


class CacheHandler:
    """Used to save, load, and remove JSON cache files.
    Filesystem access is delegated to BinaryCacheHandler,
    this class adds JSON layer.
    """
    def __init__(self, filepath: str):
        self._fp = Path(filepath)
        self._binary_cache = BinaryCacheHandler(filepath)

    @property
    def exists(self):
        """True if the cache file exists and False otherwise."""
        return self._binary_cache.exists

    def save(self, newdata: dict):
        """Save data to cache file."""
        self._binary_cache.save(json.dumps(newdata, indent=4).encode("utf-8"))

    def load(self):
        """
        Load data from cache file, if it exists.
        If it exists, but content is not valid json, None is returned instead.
        """
        rawdata = self._binary_cache.load()
        if rawdata is None:
            return None

        try:
            return json.loads(rawdata.decode("utf-8"))
        except (json.decoder.JSONDecodeError, UnicodeDecodeError):
            filename = os.path.basename(self._fp)
            logger.warning(
                msg=f"Unable to decode JSON file \"{filename}\"",
                category="cache", event="load", exc_info=True
            )
            return None

    def remove(self):
        """ Remove cache from disk."""
        self._binary_cache.remove()


class BinaryCacheHandler:
    """Used to manage binary cache files."""
    def __init__(self, filepath: str):
        self._fp = Path(filepath)

    @property
    def exists(self):
        """True if the cache file exists and False otherwise."""
        return self._fp.is_file()

    def save(self, data: bytes):
        """Save data to cache file."""
        self._fp.parent.mkdir(parents=True, exist_ok=True)
        self._fp.write_bytes(data)

    def load(self):
        """Load data from cache file, if it exists."""
        if not self.exists:
            return None
        return self._fp.read_bytes()

    def remove(self):
        """ Remove cache from disk."""
        if self.exists:
            self._fp.unlink()
