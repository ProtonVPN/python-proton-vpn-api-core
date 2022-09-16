import pytest
import tempfile
from proton.vpn.core_api import vpn_logging as logging
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
