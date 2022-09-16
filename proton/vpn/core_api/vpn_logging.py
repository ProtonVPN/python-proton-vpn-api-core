import datetime
import logging
from logging import Logger
import os
from logging.handlers import RotatingFileHandler

from proton.utils.environment import ExecutionEnvironment


def _format_log_attributes(category, subcategory, event, optional, msg):
    """Format the log message as per Proton VPN guidelines.

        param category: Category of a log, uppercase.
        :type category: string
        param subcategory: Subcategory of a log, uppercase (optional).
        :type subcategory: string
        param event: Event of a log, uppercase.
        :type event: string
        param optional: Additional contextual data (optional).
        :type optional: string
        param msg: The message, should contain all necessary details that
            help better understand the reason behind the message.
        :type msg: string
    """
    _category = f"{category}" if category else ""
    _subcategory = f".{subcategory}" if subcategory else ""
    _event = f":{event}" if event else ""
    _optional = f" | {optional}" if optional else ""
    _msg = f" | {msg}" if msg else ""

    return f"{_category.upper()}{_subcategory.upper()}{_event.upper()}{_msg}{_optional}"


def _patch_log_methods(logger: Logger, method_name: str):
    """Patch default log methods with custom ones.

    Since the default logger does not accept any extra arguments, we need to wrap the
    default methods with our custom ones, so that we can allow clients to use the arguments
    exposed on `new_method()`.
    """
    original_method = getattr(logger, method_name)

    def new_method(msg, *args, category="", subcategory="", event="", optional="", **kwargs):
        msg = _format_log_attributes(category, subcategory, event, optional, msg)
        original_method(msg, *args, **kwargs)

    setattr(logger, method_name, new_method)


def getLogger(name):
    logger = logging.getLogger(name)

    for method_name in ["debug", "info", "warning", "error", "exception", "critical"]:
        _patch_log_methods(logger, method_name)

    return logger


def config(filename, logdirpath=None):
    """Configure root logger.

        param filename: Log filename without extension.
        :type filename: string
        param logdirpath: Path to log file (optional).
        :type logdirpath: string
    """
    logger = logging.getLogger()
    logging_level = logging.INFO
    log_filepath = logdirpath

    if filename is None:
        raise ValueError("Filename must be set")

    filename = filename + ".log"

    if logdirpath is None:
        logdirpath = ExecutionEnvironment().path_cache
        log_filepath = os.path.join(logdirpath, filename)

    _formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s| %(message)s",
    )
    _formatter.formatTime = (
        lambda record, datefmt=None: datetime.datetime.utcnow().isoformat()
    )

    # Starts a new file at 3MB size limit
    _handler_file = RotatingFileHandler(
        log_filepath, maxBytes=3145728, backupCount=3
    )
    _handler_file.setFormatter(_formatter)

    # Handler to log to console
    _handler_console = logging.StreamHandler()
    _handler_console.setFormatter(_formatter)

    # Only log debug when using PROTON_VPN_DEBUG=true
    if os.environ.get("PROTON_VPN_DEBUG", "false").lower() == "true":
        logging_level = logging.DEBUG

    # Only log to terminal when using PROTON_VPN_LIVE=true
    if not _handler_console:
        logger.warning("Console logger is not set.")

    if os.environ.get("PROTON_VPN_LOG_TERMINAL", "false").lower() == "true":
        logger.addHandler(_handler_console)

    logger.setLevel(logging_level)
    if _handler_file:
        logger.addHandler(_handler_file)


__all__ = ["getLogger", "config"]
