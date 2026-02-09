# You need to copy your secrets from the keyring proton vpn entry you are using
# to log in, into a file called 'secrets.json'.
# 
# Then you need to add a 'server' key entry to that file, with the domain name
# of the server that will contain the local agent server.
# 
# You can find the domain name by looking into the serverlist cache file.

import json
import base64
import os
import cryptography
from cryptography.hazmat.primitives.serialization import Encoding, \
                                                         PrivateFormat
from cryptography.hazmat.primitives import serialization
from dataclasses import dataclass


SECRETS_FILENAME = "secrets.json"

path = os.path.abspath(__file__).split("/")
path[-1] = SECRETS_FILENAME
FILEPATH = "/".join(path)


@dataclass
class Secrets:
    certificate: str
    server_domain: str
    private_key: str


def load_secrets():
    # Load the private key and certificate from secrets.json
    #
    # You need to make secrets.json yourself, buy copying the secrets from your
    # ProtonVPN keyring.
    with open(FILEPATH, "r", encoding="utf-8") as f:
        secrets = json.load(f)

    # The certificate
    certificate = secrets["vpn"]["certificate"]["Certificate"]
    server_domain = secrets["server"]

    # The private key
    private_key = base64.b64decode(secrets["vpn"]["secrets"]["ed25519_privatekey"])
    private_key = cryptography.hazmat.primitives.asymmetric\
                    .ed25519.Ed25519PrivateKey.from_private_bytes(private_key)

    private_key = private_key.private_bytes(
                encoding=Encoding.PEM, format=PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode("ascii")

    return Secrets(certificate, server_domain, private_key)

