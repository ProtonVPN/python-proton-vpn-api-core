"""
Copyright (c) 2023 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton VPN is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
import base64
import hashlib
from typing import Optional

import cryptography.hazmat.primitives.asymmetric
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from cryptography.hazmat.primitives import serialization
import nacl.bindings


class KeyHandler:  # pylint: disable=missing-class-docstring

    PREFIX_SK = bytes(
        [int(x, 16) for x in '30:2E:02:01:00:30:05:06:03:2B:65:70:04:22:04:20'.split(':')]
    )
    PREFIX_PK = bytes([int(x, 16) for x in '30:2A:30:05:06:03:2B:65:70:03:21:00'.split(':')])

    def __init__(self, private_key=None):
        """ private key parameter must be in ed25519 format,
            from which we convert to x25519 format with nacl.
            But it's not possible to convert from x25519 to ed25519.
        """
        self._private_key, self._public_key = self.__generate_key_pair(private_key=private_key)
        tmp_ed25519_sk = self.ed25519_sk_bytes
        tmp_ed25519_pk = self.ed25519_pk_bytes
        """
        # crypto_sign_ed25519_sk_to_curve25519() is equivalent to :
        tmp = list(hashlib.sha512(ed25519_sk).digest()[:32])
        tmp[0] &= 248
        tmp[31] &= 127
        tmp[31] |= 64
        self._x25519_sk = bytes(tmp)
        """
        self._x25519_sk = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(
            tmp_ed25519_sk + tmp_ed25519_pk
        )
        self._x25519_pk = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(tmp_ed25519_pk)

    @classmethod
    def get_proton_fingerprint_from_x25519_pk(cls, x25519_pk: bytes) -> str:  # noqa: E501 pylint: disable=missing-function-docstring
        return base64.b64encode(hashlib.sha512(x25519_pk).digest()).decode("ascii")

    @classmethod
    def from_sk_file(cls, ed25519sk_file):  # pylint: disable=missing-function-docstring
        backend_default = None
        # cryptography.sys.version_info not available in 2.6
        crypto_major, crypto_minor = cryptography.__version__.split(".")[:2]

        if int(crypto_major) < 3 or \
           int(crypto_major) == 3 and \
           int(crypto_minor) < 1:

            # backend is required if library < 3.1
            backend_default = cryptography.hazmat.backends.default_backend()

        with open(file=ed25519sk_file) as file:  # pylint: disable=unspecified-encoding
            pem_data = "".join(file.readlines())

        key = serialization.load_pem_private_key(
            pem_data.encode("ascii"), password=None, backend=backend_default
        )

        assert isinstance(  # nosec B311, B101 # noqa: E501 # pylint: disable=line-too-long # nosemgrep: gitlab.bandit.B101
            key,
            cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey)  # nosec: B101
        private_key = key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        return KeyHandler(private_key=private_key)

    @property
    def ed25519_sk_str(self) -> str:  # pylint: disable=missing-function-docstring
        return base64.b64encode(self.ed25519_sk_bytes).decode("ascii")

    @property
    def ed25519_sk_bytes(self) -> bytes:  # pylint: disable=missing-function-docstring
        return self._private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

    @property
    def ed25519_pk_bytes(self) -> bytes:  # pylint: disable=missing-function-docstring
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    @property
    def ed25519_pk_str_asn1(self) -> bytes:  # pylint: disable=missing-function-docstring
        return base64.b64encode(self.PREFIX_PK + self.ed25519_pk_bytes)

    @property
    def ed25519_sk_pem(self) -> str:  # pylint: disable=missing-function-docstring
        return self.get_ed25519_sk_pem()

    @property
    def ed25519_pk_pem(self) -> str:  # pylint: disable=missing-function-docstring
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('ascii')

    @property
    def x25519_sk_bytes(self) -> bytes:  # pylint: disable=missing-function-docstring
        return self._x25519_sk

    @property
    def x25519_pk_bytes(self) -> bytes:  # pylint: disable=missing-function-docstring
        return self._x25519_pk

    @property
    def x25519_sk_str(self) -> str:  # pylint: disable=missing-function-docstring
        return base64.b64encode(self._x25519_sk).decode("ascii")

    @property
    def x25519_pk_str(self) -> str:  # pylint: disable=missing-function-docstring
        return base64.b64encode(self._x25519_pk).decode("ascii")

    @classmethod
    def __generate_key_pair(cls, private_key=None):
        if private_key:
            private_key = cryptography.hazmat.primitives.asymmetric\
                .ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        else:
            private_key = cryptography.hazmat.primitives.asymmetric\
                .ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    def get_ed25519_sk_pem(self, password: Optional[bytes] = None) -> str:
        """
        Returns the ed5519 private key in pem format,
        and encrypted if a password was passed.
        """
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password=password)
        else:
            encryption_algorithm = serialization.NoEncryption()

        return self._private_key.private_bytes(
            encoding=Encoding.PEM, format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        ).decode('ascii')


def bytes_to_str_hexa(b: bytes):  # pylint: disable=missing-function-docstring invalid-name
    return ":".join(["{:02x}".format(x) for x in b])  # pylint: disable=consider-using-f-string
