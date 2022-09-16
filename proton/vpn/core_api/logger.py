import logging
import os
import datetime
from logging.handlers import RotatingFileHandler
from proton.utils.environment import ExecutionEnvironment


class Logger():
    def __init__(self):
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)s | %(category)s | "
            "%(message)s",
        )
        formatter.formatTime = (lambda self, record, datefmt=None: datetime.datetime.utcnow().isoformat())
        LOGFILE = os.path.join(ExecutionEnvironment().path_logs, "protonvpn.log")
        self._logger = logging.getLogger("protonvpn-core")

        # Only log debug when using PROTONVPN_DEBUG=1
        if str(os.environ.get("PROTON_DEBUG", False)).lower() == "true":
            logging_level = logging.DEBUG
        else:
            logging_level = logging.INFO

        # Set logging level
        self._logger.setLevel(logging_level)

        # Starts a new file at 3MB size limit
        file_handler = RotatingFileHandler(
            LOGFILE, maxBytes=3145728, backupCount=3
        )
        file_handler.setFormatter(formatter)
        self._logger.addHandler(file_handler)

    def debug(self, msg, category="", subcategory="", event="", optional=""):
        self._logger.debug(
            msg,
            extra={
                "category": self._generate_category(category, subcategory, event, optional),
            }
        )

    def info(self, msg, category="", subcategory="", event="", optional=""):
        self._logger.info(
            msg,
            extra={
                "category": self._generate_category(category, subcategory, event, optional),
            }
        )

    def warning(self, msg, category="", subcategory="", event="", optional=""):
        self._logger.warning(
            msg,
            extra={
                "category": self._generate_category(category, subcategory, event, optional),
            }
        )

    def error(self, msg, category="", subcategory="", event="", optional=""):
        self._logger.error(
            msg,
            extra={
                "category": self._generate_category(category, subcategory, event, optional),
            }
        )

    def exception(self, msg, category="", subcategory="", event="", optional=""):
        self._logger.exception(
            msg,
            extra={
                "category": self._generate_category(category, subcategory, event, optional),
            }
        )

    def critical(self, msg, category="", subcategory="", event="", optional=""):
        self._logger.critical(
            msg,
            extra={
                "category": self._generate_category(category, subcategory, event, optional),
            }
        )

    def set_logging_level(self, newlevel):
        if newlevel not in [logging.CRITICAL, logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]:
            raise ValueError("Invalid loggig level")

        self._logger.setLevel(newlevel)

    def _generate_category(self, category, subcategory, event, optional):
        subcategory = f".{subcategory}" if subcategory else ""
        event = f":{event}" if event else ""
        optional = f" | {optional}" if optional else ""

        return f"{category.upper()}{subcategory.upper()}{event.upper()}{optional}"


logger = Logger()

__all__ = ["logger"]
