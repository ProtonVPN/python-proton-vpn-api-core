"""
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
from pathlib import Path


class CacheFile:
    """
    Persists/loads a python dictionary to disk.
    """
    def __init__(self, file_path: Path):
        """
        :param file_path: Path from/to which load/persist the cache data.
        """
        self.file_path = file_path

    @property
    def exists(self):
        """True if the cache file exists and False otherwise."""
        return self.file_path.is_file()

    def save(self, data: dict) -> None:
        """Persists the dictionary to the current file path."""
        CacheFile.to_path(data, self.file_path)

    @staticmethod
    def to_path(data: dict, file_path: Path) -> None:
        """Persists the dictionary to the given path."""
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(obj=data, fp=file)

    def load(self) -> dict:
        """
        Loads the dictionary from the current file path.

        :returns: the loaded dictionary.
        :raises ValueError: if the file content is invalid.
        :raises FileNotFoundError: if the file was not found.
        """
        return CacheFile.from_path(self.file_path)

    @staticmethod
    def from_path(file_path: Path) -> dict:
        """
        Loads a dictionary from a given file path.

        :param: file_path: path to the file to load as dictionary.
        :returns: the loaded dictionary.
        :raises ValueError: if the file content is invalid.
        :raises FileNotFoundError: if the file was not found.
        """
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)

    def remove(self) -> None:
        """Removes the current persistence file, if exists."""
        self.file_path.unlink(missing_ok=True)
