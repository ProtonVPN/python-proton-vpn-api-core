#!/usr/bin/env python3

import io
import json
import logging
import pytest

import proton.vpn.platform.core
import proton.vpn.platform.local_agent as local_agent

@pytest.fixture(scope="module")
def setup_logger():
    log_stream = io.StringIO()
    logger = proton.vpn.platform.init_logger(logging.getLogger)
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(log_stream)
    handler.setFormatter(logging.Formatter(
        '%(levelname)s:%(name)s:%(lineno)d:%(message)s'))
    logger.addHandler(handler)

    def log_output():
        return log_stream.getvalue()

    yield logger, log_output


@pytest.mark.asyncio
async def test_logging(setup_logger):
    logger, log_output = setup_logger
    logger.setLevel(logging.DEBUG)

    agent_connection = await local_agent.AgentConnector().playback(
       json.dumps(
          [[0, {"status": {"state": "connected"}}],]
       )
    )

    await agent_connection.read()
    await agent_connection.close()

    expected = (
        "INFO:proton.vpn.platform/transport_playback.rs:43:TransportPlayback::new\n"
        "INFO:proton.vpn.platform/transport_playback.rs:73:TransportPlayback:recv() -> Response { status: Some(StatusMessage { state: Connected, reason: None, features: None, connection_details: None, features_statistics: None }), error: None }\n"
        "INFO:proton.vpn.platform/transport_playback.rs:80:TransportPlayback:close()\n"
    )

    actual = log_output()

    print(actual)

    assert expected == actual
