#!/usr/bin/env python3
'''
Test setting up the local agent logger.
'''
import logging
import local_agent

logging.basicConfig()

logger = local_agent.init_logger(logging.getLogger)
logger.setLevel(logging.DEBUG)

logger.info("hello", extra={"rust_info" : {"name" : "dave", "lineno" : 123}})
