import asyncio
import local_agent

# Connect to the VPN server
async def make_test_connection():
    agent_connection = await local_agent.AgentConnector().playback("responses.json")

    print(await agent_connection.read())
    print(await agent_connection.read())

    await agent_connection.close()

# execute the coroutine
asyncio.run(make_test_connection())
