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
from typing import Callable, Optional
from proton.vpn import logging


logger = logging.getLogger(__name__)


class CacheHandler:
    """Used to save, load, and remove cache files."""
    def __init__(
            self,
            filepath: str,
            object_hook_factory: Optional[
                Callable[[], Callable[[dict], dict]]
            ] = None
    ):
        self._fp = Path(filepath)
        self._object_hook_factory = object_hook_factory

    @property
    def exists(self):
        """True if the cache file exists and False otherwise."""
        return self._fp.is_file()

    def save(self, newdata: dict):
        """Save data to cache file."""
        self._fp.parent.mkdir(parents=True, exist_ok=True)
        with open(self._fp, "w", encoding="utf-8") as f:  # pylint: disable=C0103
            json.dump(newdata, f, indent=4)  # pylint: disable=C0103

    def load(self):
        """
        Load data from cache file, if it exists.
        If it exists, but content is not valid json, None is returned instead.
        """
        if not self.exists:
            return None

        try:
            with open(self._fp, "r", encoding="utf-8") as f:  # pylint: disable=C0103
                object_hook = self._object_hook_factory() \
                    if self._object_hook_factory else None
                return json.load(  # pylint: disable=C0103
                    f, object_hook=object_hook
                )
        except (json.decoder.JSONDecodeError, UnicodeDecodeError):
            filename = os.path.basename(self._fp)
            logger.warning(
                msg=f"Unable to decode JSON file \"{filename}\"",
                category="cache", event="load", exc_info=True
            )
            return None

    def remove(self):
        """ Remove cache from disk."""
        if self.exists:
            os.remove(self._fp)
