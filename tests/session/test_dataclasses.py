import pytest
from proton.vpn.core.session.dataclasses import asdict, VPNSettings, VPNSessions, VPNInfo, VPNCertificate, APIVPNSession, VPNLocation


@pytest.fixture
def vpninfo_data():
    return {
        "ExpirationTime": 1,
        "Name": "random_user",
        "Password": "asdKJkjb12",
        "GroupID": "test-group",
        "Status": 1,
        "PlanName": "test plan",
        "PlanTitle": "test title",
        "MaxTier": 1,
        "MaxConnect": 1,
        "Groups": ["group1", "group2"],
        "NeedConnectionAllocation": False,
    }


def test_vpninfo_deserializes_expected_dict_keys(vpninfo_data):
    vpninfo = VPNInfo.from_dict(vpninfo_data)

    assert asdict(vpninfo) == vpninfo_data


def test_vpninfo_deserialize_should_not_crash_with_unexpected_dict_keys(vpninfo_data):
    vpninfo_data["unexpected_keyword"] = "keyword and data"
    VPNInfo.from_dict(vpninfo_data)


@pytest.fixture
def vpnsettings_data(vpninfo_data):
    return {
        "VPN": vpninfo_data,
        "Services": 1,
        "Subscribed": 1,
        "Delinquent": 0,
        "HasPaymentMethod": 1,
        "Credit": 1234,
        "Currency": "€",
        "Warnings": [],
    }


def test_vpnsettings_deserializes_expected_dict_keys(vpnsettings_data):
    vpnsettings = VPNSettings.from_dict(vpnsettings_data)

    assert asdict(vpnsettings) == vpnsettings_data


def test_vpnsettings_deserialize_should_not_crash_with_unexpected_dict_keys(vpnsettings_data):
    vpnsettings_data["unexpected_keyword"] = "keyword and data"
    VPNSettings.from_dict(vpnsettings_data)


@pytest.fixture
def vpncertificate_data():
    return {
        "SerialNumber": "asd879hnna!as",
        "ClientKeyFingerprint": "fingerprint",
        "ClientKey": "as243sdfs4",
        "Certificate": "certificate",
        "ExpirationTime": 123456789,
        "RefreshTime": 123456789,
        "Mode": "on",
        "DeviceName": "mock-device",
        "ServerPublicKeyMode": "mock-mode",
        "ServerPublicKey": "mock-key"
    }


def test_vpncertificate_deserializes_expected_dict_keys(vpncertificate_data):
    vpncertificate = VPNCertificate.from_dict(vpncertificate_data)

    assert asdict(vpncertificate) == vpncertificate_data


def test_vpncertificate_deserialize_should_not_crash_with_unexpected_dict_keys(vpncertificate_data):
    vpncertificate_data["unexpected_keyword"] = "keyword and data"
    VPNCertificate.from_dict(vpncertificate_data)


@pytest.fixture
def vpnsession_data():
    return {
        "SessionID": "session1",
        "ExitIP": "2.2.2.1",
        "Protocol": "openvpn-tcp",
    }


def test_vpnsession_deserializes_expected_dict_keys(vpnsession_data):
    vpnsession = APIVPNSession.from_dict(vpnsession_data)

    assert asdict(vpnsession) == vpnsession_data


def test_vpnsession_deserialize_should_not_crash_with_unexpected_dict_keys(vpnsession_data):
    vpnsession_data["unexpected_keyword"] = "keyword and data"

    APIVPNSession.from_dict(vpnsession_data)


@pytest.fixture
def vpnsessions_data():
    return {
        "Sessions": [
            {
                "SessionID": "session1",
                "ExitIP": "2.2.2.1",
                "Protocol": "openvpn-tcp",
            },
            {
                "SessionID": "session2",
                "ExitIP": "2.2.2.3",
                "Protocol": "openvpn-udp",
            },
            {
                "SessionID": "session3",
                "ExitIP": "2.2.2.53",
                "Protocol": "wireguard",
            }
        ]
    }


def test_vpnsessions_deserializes_expected_dict_keys(vpnsessions_data):
    vpnsessions = VPNSessions.from_dict(vpnsessions_data)

    assert asdict(vpnsessions) == vpnsessions_data


def test_vpnsessions_deserialize_should_not_crash_with_unexpected_dict_keys(vpnsessions_data):
    vpnsessions_data["unexpected_keyword"] = "keyword and data"

    VPNSessions.from_dict(vpnsessions_data)


@pytest.fixture
def vpnlocation_data():
    return {
        "IP": "192.168.0.1",
        "Lat": 46.204391,
        "Long": 6.143158,
        "Country": "Switzerland",
        "ISP": "SwissRandomProvider",
    }


def test_vpnlocation_deserializes_expected_dict_keys(vpnlocation_data):
    vpnlocation = VPNLocation.from_dict(vpnlocation_data)

    assert asdict(vpnlocation) == vpnlocation_data


def test_vpnlocation_deserialize_should_not_crash_with_unexpected_dict_keys(vpnlocation_data):
    vpnlocation_data["unexpected_keyword"] = "keyword and data"

    VPNLocation.from_dict(vpnlocation_data)
