'''
This tests that local_agent.AgentConnection() can be used to connect to a VPN
server.
If no exception are raised during the call to AgentConnection.connect(), then
the test is successful.

You need to copy your secretes from the keyring proton vpn entry you are using
to log in, into a file called 'secrets.json'

Then you need to add a 'server' key entry to that file, with the domain name
of the server that will contain the local agent server.

You can find the domain name by looking into the serverlist cache file.

For this test to work it's required to be connected to be connected to a server,
and passing a domain that matches that server to the `secrets.json` file.
'''
import os
import asyncio
import local_agent
import json
import base64
import cryptography
from cryptography.hazmat.primitives.serialization import Encoding, \
                                                         PrivateFormat
from cryptography.hazmat.primitives import serialization

SECRETS_FILENAME = "secrets.json"
path = os.path.abspath(__file__).split("/")
path[-1] = SECRETS_FILENAME
FILEPATH = "/".join(path)
# Load the private key and certificate from secrets.json
#
# You need to make secrets.json yourself, buy copying the secrets from your
# ProtonVPN keyring.
with open(FILEPATH, "r", encoding="utf-8") as f:
    secrets = json.load(f)

# The certificate
certificate = secrets["vpn"]["certificate"]["Certificate"]
server = secrets["server"]

# The private key
private_key = base64.b64decode(secrets["vpn"]["secrets"]["ed25519_privatekey"])
private_key = cryptography.hazmat.primitives.asymmetric\
                .ed25519.Ed25519PrivateKey.from_private_bytes(private_key)

private_key = private_key.private_bytes(
            encoding=Encoding.PEM, format=PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("ascii")

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
        server, private_key, certificate, timeout)

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
