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
import datetime
import enum
import hashlib
import typing
import nacl.bindings
import cryptography.x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import cryptography.hazmat.backends


class Asn1BerDecoder:  # pylint: disable=missing-class-docstring

    _TYPE_INTEGER = 0x02
    _TYPE_OCTET_STR = 0x04
    _TYPE_SEQUENCE = 0x10
    _TYPE_SEQUENCE_OF = 0x30

    @classmethod
    def __get_asn1_ber_len(cls, raw: bytes) -> typing.Tuple[int, int]:
        """ returns : tuple (length, position start of data) """
        # byte 0 : data type
        if raw[1] & 0x80 == 0:
            # The short form is a single byte, between 0 and 127.
            return raw[1], 2

        # The long form is at least two bytes long, and has bit 8 of the first byte set to 1.
        # Bits 7-1 of the first byte indicate how many more bytes are in
        # the length field itself.
        # Then the remaining bytes specify the length itself, as a multi-byte integer.
        length_of_length = raw[1] & 0x7f
        data_len = 0
        for b in raw[2:2 + length_of_length]:  # pylint: disable=invalid-name
            data_len = data_len * 256 + b
        return data_len, length_of_length + 2

    @classmethod
    def _transform_value_to_str_no_len_check(cls, raw: bytes) -> typing.Tuple[str, int]:
        """ returns : tuple (decoded string, total length) """
        if raw[0] != cls._TYPE_OCTET_STR:
            raise ValueError(f"Not a string : {raw}")
        data_len, pos_data = cls.__get_asn1_ber_len(raw)
        return raw[pos_data:pos_data + data_len].decode("ascii"), (pos_data + data_len)

    @classmethod
    def transform_value_to_str(cls, raw: bytes) -> str:  # noqa: E501 pylint: disable=missing-function-docstring
        data, total_len = cls._transform_value_to_str_no_len_check(raw)
        if total_len != len(raw):
            raise ValueError(
                F"wrong extension length : {raw} , found {total_len}, expected {len(raw)}"
            )
        return data

    @classmethod
    def _transform_value_to_int_no_len_check(cls, raw: bytes) -> typing.Tuple[int, int]:
        """ returns : tuple (decoded int, total length) """
        if raw[0] != cls._TYPE_INTEGER:
            raise ValueError(f"Not an integer : {raw}")
        data_len, pos_data = cls.__get_asn1_ber_len(raw)
        val = 0
        for b in raw[pos_data:pos_data + data_len]:  # pylint: disable=invalid-name
            val = val * 256 + b
        return val, (pos_data + data_len)

    @classmethod
    def transform_value_to_int(cls, raw: bytes) -> int:  # noqa: E501 pylint: disable=missing-function-docstring
        data, total_len = cls._transform_value_to_int_no_len_check(raw)
        if total_len != len(raw):
            raise ValueError(
                f"wrong extension length : {raw} , found {total_len}, expected {len(raw)}"
            )
        return data

    @classmethod
    def _transform_value_to_sequence_no_len_check(cls, raw: bytes) -> typing.Tuple[list, int]:
        """ returns : tuple (decoded list, total length) """
        if raw[0] not in (cls._TYPE_SEQUENCE, cls._TYPE_SEQUENCE_OF):
            raise ValueError(f"Not a sequence : {raw}")
        data_len, pos_data = cls.__get_asn1_ber_len(raw)

        indefinite_len = bool(data_len == 0 and raw[1] == 0x80)
        decoded_list = []
        current_pos = pos_data
        while True:
            if indefinite_len:
                # Indefinite length : the end is indicated by the two bytes 00 00
                if raw[current_pos] == 0 and raw[current_pos + 1] == 0:
                    current_pos += 2
                    if current_pos != len(raw):
                        raise ValueError(
                            f"wrong extension length : {raw} , "
                            f"indefinite len ending at position {data_len}, expected {len(raw)}"
                        )
                    break
            else:
                if current_pos == pos_data + data_len:
                    break

                if current_pos > pos_data + data_len:
                    raise IndexError(
                        f"Error parsing data : current_pos = {current_pos} / "
                        f"pos_data = {pos_data} / data_len = {data_len} / raw = {raw}"
                    )

            if raw[current_pos] == cls._TYPE_INTEGER:
                tmp, tmp_len = cls._transform_value_to_int_no_len_check(raw[current_pos:])
                decoded_list.append(tmp)
                current_pos += tmp_len
            elif raw[current_pos] == cls._TYPE_OCTET_STR:
                tmp, tmp_len = cls._transform_value_to_str_no_len_check(raw[current_pos:])
                decoded_list.append(tmp)
                current_pos += tmp_len
            elif raw[current_pos] in (cls._TYPE_SEQUENCE, cls._TYPE_SEQUENCE_OF):
                tmp, tmp_len = cls._transform_value_to_sequence_no_len_check(raw[current_pos:])
                decoded_list.append(tmp)
                current_pos += tmp_len
            else:
                raise NotImplementedError(
                    f"Unknown type found : 0x{raw[current_pos]:02x} "
                    f"at position {current_pos} in raw = {raw}"
                )
        return decoded_list, current_pos

    @classmethod
    def transform_value_to_sequence(cls, raw: bytes) -> list:  # noqa: E501 pylint: disable=missing-function-docstring
        data, total_len = cls._transform_value_to_sequence_no_len_check(raw)
        if total_len != len(raw):
            raise ValueError(
                f"wrong extension length : {raw} , found {total_len}, expected {len(raw)}"
            )
        return data


class Extension:  # pylint: disable=missing-class-docstring

    def __init__(self, cert_ext: cryptography.x509.extensions.Extension):
        self._cert_ext = cert_ext

    @property
    def critical(self) -> bool:  # pylint: disable=missing-function-docstring
        return self._cert_ext.critical

    @property
    def oid(self) -> str:  # pylint: disable=missing-function-docstring
        return self._cert_ext.oid.dotted_string

    @property
    def value(self):
        """
        raw ASN1 value (bytes) : self.value.value
        """
        return self._cert_ext.value.value

    @property
    def raw(self):
        """
        Examples :
        OID as string : self.raw.oid.dotted_string
        raw ASN1 value (bytes) : self.raw.value.value
        """
        return self._cert_ext

    @property
    def value_as_str(self) -> str:  # pylint: disable=missing-function-docstring
        return Asn1BerDecoder.transform_value_to_str(self.value)

    @property
    def value_as_int(self) -> int:  # pylint: disable=missing-function-docstring
        return Asn1BerDecoder.transform_value_to_int(self.value)

    @property
    def value_as_sequence(self) -> list:  # pylint: disable=missing-function-docstring
        return Asn1BerDecoder.transform_value_to_sequence(self.value)

    def __str__(self):
        return str(self._cert_ext)

    def __repr__(self):
        return repr(self._cert_ext)


class ExtName(enum.Enum):  # pylint: disable=missing-class-docstring

    # https://confluence.protontech.ch/display/VPN/Agent+features+directory+and+format

    _TWO_FACTORS = "0.0.0"
    USER_TIER = "0.0.1"
    GROUPS = "0.0.2"
    PLATFORM = "0.0.3"
    NETSHIELD = "0.1.0"
    PORT_FW = "0.1.3"
    JAIL = "0.1.5"
    SPLIT_TCP = "0.1.6"
    RANDOM_NAT = "0.1.7"
    BOUNCING = "0.1.8"
    SAFE_MODE = "0.1.9"


class Certificate:  # pylint: disable=missing-class-docstring

    PROTONVPN_OID_STR = '1.3.6.1.4.1.56809.1'
    PROTONVPN_OID_ARRAY = PROTONVPN_OID_STR.split(".")

    def __init__(self, cert_pem: typing.Union[bytes, str] = None, cert_der: bytes = None):

        cert_input = [(cert_pem, "PEM"), (cert_der, "DER")]
        cert_input = [(x, x_type) for x, x_type in cert_input if x is not None]

        if len(cert_input) > 1:
            raise ValueError(
                "Not possible to provide multiple cert format. "
                f"Provided formats = {'/'.join([x_type for _, x_type in cert_input])}"
            )

        backend_x509 = None

        # cryptography.sys.version_info not available in 2.6
        crypto_major, crypto_minor = cryptography.__version__.split(".")[:2]

        if (
            int(crypto_major) < 3
            or int(crypto_major) == 3 and int(crypto_minor) < 1
        ):
            # backend is required if library < 3.1
            backend_x509 = cryptography.hazmat.backends.default_backend()

        if cert_pem is not None:
            if isinstance(cert_pem, str):
                cert_pem = cert_pem.encode("ascii")
            self._cert = cryptography.x509.load_pem_x509_certificate(
                data=cert_pem, backend=backend_x509
            )
        elif cert_der is not None:
            self._cert = cryptography.x509.load_der_x509_certificate(
                data=cert_der, backend=backend_x509
            )
        else:
            raise ValueError("Not provided any cert format")

    @property
    def raw(self):  # pylint: disable=missing-function-docstring
        return self._cert

    @property
    def public_key(self) -> bytes:  # pylint: disable=missing-function-docstring
        return self._cert.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    @property
    def proton_fingerprint(self) -> str:  # pylint: disable=missing-function-docstring
        ed25519_pk = self.public_key
        x25519_pk = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(ed25519_pk)
        return self.get_proton_fingerprint_from_x25519_pk(x25519_pk)

    @property
    def has_valid_date(self) -> bool:  # pylint: disable=missing-function-docstring
        return self.validity_period >= 0

    @property
    def validity_period(self) -> float:
        """ remaining time the certificate is valid,
            in seconds. < 0 : certificate is not valid anymore.
        """
        now_timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()
        return self.validity_date.timestamp() - now_timestamp

    @property
    def validity_date(self) -> datetime.datetime:  # pylint: disable=missing-function-docstring
        # cryptography >= v42.0.0 added `not_valid_after_utc` and deprecated `not_valid_after`.
        if hasattr(self._cert, "not_valid_after_utc"):
            return self._cert.not_valid_after_utc

        # Because `not_valid_after` returns a naive utc
        # datetime object (without time zone info), we add it manually.
        return self._cert.not_valid_after.replace(
            tzinfo=datetime.timezone.utc
        )

    @property
    def issued_date(self) -> datetime.datetime:  # pylint: disable=missing-function-docstring
        # cryptography >= v42.0.0 added `not_valid_before_utc` and deprecated `not_valid_before`.
        if hasattr(self._cert, "not_valid_before_utc"):
            return self._cert.not_valid_before_utc

        # Because `not_valid_before` returns a naive utc
        # datetime object (without time zone info), we add it manually.
        return self._cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)

    @property
    def duration(self) -> datetime.timedelta:
        """ certification duration """
        return self.validity_date - self.issued_date

    @classmethod
    def get_proton_fingerprint_from_x25519_pk(cls, x25519_pk: bytes) -> str:  # noqa: E501 pylint: disable=missing-function-docstring
        return base64.b64encode(hashlib.sha512(x25519_pk).digest()).decode("ascii")

    def get_as_der(self) -> bytes:  # pylint: disable=missing-function-docstring
        return self._cert.public_bytes(Encoding.DER)

    def get_as_pem(self) -> str:  # pylint: disable=missing-function-docstring
        return self._cert.public_bytes(Encoding.PEM).decode("ascii")

    @property
    def proton_extensions(self) -> typing.Dict[ExtName, Extension]:  # noqa: E501 pylint: disable=missing-function-docstring
        extensions = {}
        for ext in self._cert.extensions:
            oid_array = ext.oid.dotted_string.split(".")
            if oid_array[:len(self.PROTONVPN_OID_ARRAY)] == self.PROTONVPN_OID_ARRAY:
                try:
                    ext_name = ".".join(oid_array[len(self.PROTONVPN_OID_ARRAY):])
                    ext_name = ExtName(ext_name)
                except ValueError:
                    continue
                extensions[ext_name] = Extension(ext)
        return extensions
