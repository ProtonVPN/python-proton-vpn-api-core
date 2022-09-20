import logging
import tempfile

from proton.vpn.core_api import vpn_logging

vpn_logging.config("tests", tempfile.gettempdir())
logger = vpn_logging.getLogger(__name__)
logger = vpn_logging.getLogger(__name__)  # get same logger again to see if it introduces side effects
logger.setLevel(logging.DEBUG)

logger.log(logging.DEBUG, "log", category="category", subcategory="subcategory", event="event", optional="optional")
logger.debug("debug", category="category", subcategory="subcategory", event="event", optional="optional")
logger.info("info", category="category", subcategory="subcategory", event="event", optional="optional")
logger.warning("warning", category="category", subcategory="subcategory", event="event", optional="optional")
logger.error("error", category="category", subcategory="subcategory", event="event", optional="optional")
try:
    raise Exception
except Exception:
    logger.exception("exception", category="category", subcategory="subcategory", event="event", optional="optional")

logger.info("info-no-attrs")
