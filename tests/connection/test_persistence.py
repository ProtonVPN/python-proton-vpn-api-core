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
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from proton.vpn.connection.persistence import ConnectionPersistence, ConnectionParameters


@pytest.fixture
def temp_dir() -> str:
    with TemporaryDirectory(suffix=__name__) as temp_dir:
        yield f"{temp_dir}"


def test_load(temp_dir: str):
    with open(os.path.join(temp_dir, ConnectionPersistence.FILENAME), "w") as f:
        f.write(
            '{"connection_id": "connection_id", "backend": "backend", '
            '"protocol": "protocol", "server_id": "server_id", '
            '"server_name": "server_name", "server_domain": "server_domain", '
            '"?": "1"}'
        )

    connection_persistence = ConnectionPersistence(persistence_directory=temp_dir)
    persisted_parameters = connection_persistence.load()

    assert persisted_parameters.connection_id == "connection_id"
    assert persisted_parameters.backend == "backend"
    assert persisted_parameters.protocol == "protocol"
    assert persisted_parameters.server_id == "server_id"
    assert persisted_parameters.server_name == "server_name"
    assert persisted_parameters.server_domain == "server_domain"


def test_load_returns_none_and_logs_error_when_persistence_file_contains_invalid_json(temp_dir, caplog):
    with open(os.path.join(temp_dir, ConnectionPersistence.FILENAME), "w") as f:
        f.write('{"conn')

    connection_persistence = ConnectionPersistence(persistence_directory=temp_dir)
    persisted_parameters = connection_persistence.load()

    assert not persisted_parameters
    assert len([r for r in caplog.records if r.levelname == "ERROR"]) == 1


def test_load_returns_none_and_logs_error_when_persistence_file_misses_expected_parameters(temp_dir):
    with open(os.path.join(temp_dir, ConnectionPersistence.FILENAME), "w") as f:
        f.write('{"foo": "bar"}')

    connection_persistence = ConnectionPersistence(persistence_directory=temp_dir)
    persisted_parameters = connection_persistence.load()

    assert not persisted_parameters


def test_save_(temp_dir: str):
    connection_parameters = ConnectionParameters(
        connection_id="connection_id",
        backend="backend",
        protocol="protocol",
        server_id="server_id",
        server_name="server_name",
        server_domain="server_domain"
    )

    connection_persistence = ConnectionPersistence(persistence_directory=temp_dir)
    connection_persistence.save(connection_parameters)

    with open(os.path.join(temp_dir, ConnectionPersistence.FILENAME)) as f:
        persistence_file_content = json.load(f)

        assert connection_parameters.connection_id == persistence_file_content["connection_id"]
        assert connection_parameters.backend == persistence_file_content["backend"]
        assert connection_parameters.protocol == persistence_file_content["protocol"]
        assert connection_parameters.server_id == persistence_file_content["server_id"]
        assert connection_parameters.server_name == persistence_file_content["server_name"]
        assert connection_parameters.server_domain == persistence_file_content["server_domain"]


def test_remove(temp_dir: str):
    persistence_file_path = Path(temp_dir) / ConnectionPersistence.FILENAME
    persistence_file_path.touch()
    assert persistence_file_path.is_file()

    connection_persistence = ConnectionPersistence(persistence_directory=temp_dir)
    connection_persistence.remove()

    assert not persistence_file_path.exists()


def test_remove_logs_a_warning_when_persistence_file_was_not_found(
        temp_dir:str, caplog
):
    connection_persistence = ConnectionPersistence(persistence_directory=temp_dir)
    connection_persistence.remove()

    assert len(caplog.records) == 1
    assert len([r for r in caplog.records if r.levelname == "WARNING"]) == 1
