import asyncio
import local_agent
import json

responses = [
   [
      0,
      {
         "status" : {
            "state" : "connected"
         }
      }
   ],
   [
      1,
      {
         "status" : {
            "reason" : {
               "code" : 86111,
               "description" : "Max session reached for this plan",
               "final" : False
            },
            "state" : "hard-jailed"
         }
      }
   ]
]

# Connect to the VPN server
async def make_test_connection():
    agent_connection = await local_agent.AgentConnector().playback(json.dumps(responses))

    print(await agent_connection.read())
    print(await agent_connection.read())

    await agent_connection.close()

# execute the coroutine
asyncio.run(make_test_connection())
