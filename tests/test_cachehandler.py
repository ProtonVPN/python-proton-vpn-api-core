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
import os
import tempfile

import pytest
from proton.vpn.core.cache_handler import CacheHandler


class TestCacheHandler:
    @pytest.fixture
    def dir_path(self):
        configfolder = tempfile.TemporaryDirectory(prefix="test_cache_handler")
        yield configfolder
        configfolder.cleanup()

    @pytest.fixture
    def cache_filepath(self, dir_path):
        return os.path.join(dir_path.name, "test_cache_file.json")

    def test_save_new_cache(self, cache_filepath):
        cache_handler = CacheHandler(cache_filepath)
        cache_handler.save({"save_cache": "dummy-data"})
        with open(cache_filepath, "r") as f:
            content = json.load(f)
            assert "save_cache" in content
            assert "dummy-data" == content["save_cache"]

    def test_load_stored_cache(self, cache_filepath):
        cache_handler = CacheHandler(cache_filepath)
        with open(cache_filepath, "w") as f:
            json.dump({"load_cache": "dummy-data"}, f)

        data = cache_handler.load()
        assert "load_cache" in data
        assert "dummy-data" == data["load_cache"]

    def test_load_cache_with_missing_file(self, cache_filepath):
        cache_handler = CacheHandler(cache_filepath)
        assert not cache_handler.load()

    def test_remove_cache(self, cache_filepath):
        cache_handler = CacheHandler(cache_filepath)
        with open(cache_filepath, "w") as f:
            json.dump({"load_cache": "dummy-data"}, f)

        cache_handler.remove()

        assert not os.path.isfile(cache_filepath)
