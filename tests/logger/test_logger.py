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
import pytest
import tempfile
from proton.vpn import logging
import logging as _logging


@pytest.fixture(scope="module")
def test_logger():
    with tempfile.TemporaryDirectory() as tmpdir:
        logging.config("test-file", logdirpath=tmpdir)
        logger = logging.getLogger(__name__)
        logger.setLevel(_logging.DEBUG)
        yield logger


def log_debug(logger):
    logger.debug("test-message-debug", category="CAT", event="EV")


def log_info(logger):
    logger.info("test-message-info", category="CAT", event="EV")


def log_warning(logger):
    logger.warning("warning", category="CAT", event="EV")


def log_error(logger):
    logger.error("error", category="CAT", event="EV")


def log_critical(logger):
    logger.critical("critical", category="CAT", event="EV")


def log_exception(logger):
    try:
        raise Exception("test")
    except Exception:
        logger.exception("exception", category="CAT", event="EV")


def test_debug_with_custom_properties(caplog, test_logger):
    caplog.clear()
    log_debug(test_logger)
    for record in caplog.records:
        assert record.levelname == "DEBUG"
    assert len(caplog.records) == 1


def test_info_with_custom_properties(caplog, test_logger):
    caplog.clear()
    log_info(test_logger)
    for record in caplog.records:
        assert record.levelname == "INFO"
    assert len(caplog.records) == 1


def test_warning_with_custom_properties(caplog, test_logger):
    caplog.clear()
    log_warning(test_logger)
    for record in caplog.records:
        assert record.levelname == "WARNING"
    assert len(caplog.records) == 1


def test_error_with_custom_properties(caplog, test_logger):
    caplog.clear()
    log_error(test_logger)
    for record in caplog.records:
        assert record.levelname == "ERROR"
    assert len(caplog.records) == 1


def test_critical_with_custom_properties(caplog, test_logger):
    caplog.clear()
    log_critical(test_logger)
    for record in caplog.records:
        assert record.levelname == "CRITICAL"
    assert len(caplog.records) == 1


def test_exception_with_custom_properties(caplog, test_logger):
    caplog.clear()
    log_exception(test_logger)
    for record in caplog.records:
        assert record.levelname == "ERROR"
    assert len(caplog.records) == 1
    assert "exception" in caplog.text


def test_debug_with_only_message_logging_properties(caplog, test_logger):
    caplog.clear()
    test_logger.debug(msg="test-default-debug")
    for record in caplog.records:
        assert record.levelname == "DEBUG"
    assert len(caplog.records) == 1
    assert "test-default-debug" in caplog.text


def test_debug_with_no_logging_properties(caplog, test_logger):
    caplog.clear()
    test_logger.debug(msg="")
    assert len(caplog.records) == 1
    assert "" in caplog.text
