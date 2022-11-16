import json
import os
import tempfile

import pytest
from proton.vpn.core_api.cache_handler import CacheHandler


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
