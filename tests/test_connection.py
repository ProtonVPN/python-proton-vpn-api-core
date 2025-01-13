#!/usr/bin/env python3
'''
This tests that local_agent.AgentConnection() can be used to connect to a VPN
server.
If no exception are raised during the call to AgentConnection.connect(), then
the test is successful.

Check instructions on load_secrets.py on how to set thing up to be able to
run this test.

For this test to work it's required to be connected to be connected to a server,
and passing a domain that matches that server to the `secrets.json` file.
'''
import asyncio
import local_agent
from load_secrets import load_secrets

secrets = load_secrets()

timeout = 1 # 1 second timeout

async def do_read(connection):
    print("Waiting for read...")

    return await connection.read()

# Connect to the VPN server
async def make_test_connection():
    local_agent.init()

    agent_connector = local_agent.AgentConnector()
    print()

    agent_connection = await agent_connector.connect(
        secrets.server_domain, secrets.private_key, secrets.certificate, timeout)

    print("Local agent connection established")

    # First connection we get a status straight away
    print("Read status")
    print(await agent_connection.read())

    # Now request another status
    print("Request a new status")
    await agent_connection.request_status(timeout)
    print(await agent_connection.read())

    wait_for_read = asyncio.create_task(do_read(agent_connection))

    print("Requesting features")
    await asyncio.sleep(1)

    agent_connection.request_features( local_agent.AgentFeatures(netshield_level = 3) )

    # Now get the latest status back.
    # We should have features in it.
    status = await wait_for_read

    print(status)

    # Now try to read the netshield level directly
    print(status.features.netshield_level)

    # Now we're done with the connection
    await agent_connection.close()

# execute the coroutine
asyncio.run(make_test_connection())
