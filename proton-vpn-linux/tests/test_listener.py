#!/usr/bin/env python3
"""
Tests that we can start a LA connection and listen for status changes.

To be able to run this test you need to be connected to a VPN server
and create the secrets.json file as documented in load_secrets.py.
"""

import asyncio
import logging

from load_secrets import load_secrets


from local_agent import Listener, AgentFeatures, ExpiredCertificateError
import local_agent

logger = local_agent.init_logger(logging.getLogger)
logging.basicConfig()
logger.setLevel(logging.DEBUG)

def error_callback(error):
    logger.info(f"\nError callback: {error}")


def status_callback(status):
    logger.info(f"\nStatus callback: {status}")


async def main():
    secrets = load_secrets()

    try:
        listener = await Listener.connect(secrets.server_domain, secrets.private_key, secrets.certificate)
    except ExpiredCertificateError:
        logger.info("\nExpired certificate error")
        raise
    except TimeoutError:
        logger.info("\nTimeout error")
        raise
    except Exception:
        logger.info("\nGeneral error")
        raise

    future = listener.listen(status_callback, error_callback)
    await asyncio.sleep(1)
    await listener.request_features(AgentFeatures(netshield_level = 3))
    await asyncio.sleep(3)
    future.cancel()
    try:
        await future
    except asyncio.CancelledError:
        logger.info("Listener was stopped.")



asyncio.run(main())
