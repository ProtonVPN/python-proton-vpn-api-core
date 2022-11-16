import pytest
from proton.vpn.core_api.session import ClientConfig
import time


@pytest.fixture
def apidata():
    return {
        "Code": 1000,
        "OpenVPNConfig": {
            "DefaultPorts": {
                "UDP": [80, 51820, 4569, 1194, 5060],
                "TCP": [443, 7770, 8443]
            }
        },
        "HolesIPs": ["62.112.9.168", "104.245.144.186"],
        "ServerRefreshInterval": 10,
        "FeatureFlags": {
            "NetShield": 0, "GuestHoles": 0, "ServerRefresh": 1,
            "StreamingServicesLogos": 1, "PortForwarding": 0,
            "ModerateNAT": 1, "SafeMode": 0, "StartConnectOnBoot": 1,
            "PollNotificationAPI": 1, "VpnAccelerator": 1,
            "SmartReconnect": 1, "PromoCode": 0, "WireGuardTls": 1
        },
        "CacheExpiration": time.time()
    }


def test_from_dict_with_raw_api_data(apidata):
    client_config = ClientConfig.from_dict(apidata)

    assert client_config.openvpn_ports.udp == apidata["OpenVPNConfig"]["DefaultPorts"]["UDP"]
    assert client_config.openvpn_ports.tcp == apidata["OpenVPNConfig"]["DefaultPorts"]["TCP"]
    assert client_config.holes_ips == apidata["HolesIPs"]
    assert client_config.server_refresh_interval == apidata["ServerRefreshInterval"]
    assert client_config.feature_flags.netshield == apidata["FeatureFlags"]["NetShield"]
    assert client_config.feature_flags.guest_holes == apidata["FeatureFlags"]["GuestHoles"]
    assert client_config.feature_flags.server_refresh == apidata["FeatureFlags"]["ServerRefresh"]
    assert client_config.feature_flags.streaming_services_logos == apidata["FeatureFlags"]["StreamingServicesLogos"]
    assert client_config.feature_flags.port_forwarding == apidata["FeatureFlags"]["PortForwarding"]
    assert client_config.feature_flags.moderate_nat == apidata["FeatureFlags"]["ModerateNAT"]
    assert client_config.feature_flags.safe_mode == apidata["FeatureFlags"]["SafeMode"]
    assert client_config.feature_flags.start_connect_on_boot == apidata["FeatureFlags"]["StartConnectOnBoot"]
    assert client_config.feature_flags.poll_notification_api == apidata["FeatureFlags"]["PollNotificationAPI"]
    assert client_config.feature_flags.vpn_accelerator == apidata["FeatureFlags"]["VpnAccelerator"]
    assert client_config.feature_flags.smart_reconnect == apidata["FeatureFlags"]["SmartReconnect"]
    assert client_config.feature_flags.promo_code == apidata["FeatureFlags"]["PromoCode"]
    assert client_config.feature_flags.wireguard_tls == apidata["FeatureFlags"]["WireGuardTls"]
