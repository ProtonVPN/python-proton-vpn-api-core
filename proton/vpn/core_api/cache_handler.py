"""
Cache Handler module.
"""

import json
import os

from proton.utils.environment import VPNExecutionEnvironment

SERVER_LIST = os.path.join(
    VPNExecutionEnvironment().path_cache,
    "serverlist.json"
)
CLIENT_CONFIG = os.path.join(
    VPNExecutionEnvironment().path_cache,
    "clientconfig.json"
)


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
