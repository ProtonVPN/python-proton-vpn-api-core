import pytest
import proton.vpn.lib
import struct

STATUS_TOKEN = 'kjdkjskfjkjsdfjsdkfjksd'

LOADS = [
        {'status': 3, 'load': 50, 'partial_score': 0.5},
        {'status': 3, 'load': 25, 'partial_score': 0.75},
        {'status': 3, 'load': 75, 'partial_score': 0.25},
]


@pytest.fixture
def mock_logicals_location_country():
    logicals = {
        "StatusID": STATUS_TOKEN,
        "LogicalServers": [
            {
                "StatusReference": {
                    "Index": 0,
                    "Penalty": 0,
                    "Cost": 1,
                },
                "Domain": "se-jp-01.protonvpn.net",
                "EntryCountry": "FR",
                "ExitCountry": "FR",
                "ID": "jfskjfsdkfjksdnvknsvskdjv",
                "EntryLocation": {
                    "Latitude": 35.65,
                    "Longitude": 139.83
                },
                "ExitLocation": {
                    "Latitude": 35.65,
                    "Longitude": 139.83
                },
                "Name": "SE-JP#1",
            }
        ]
    }

    user_location = {
        "Latitude": 35.65,
        "Longitude": 139.83
    }

    user_country = "FR"

    return (logicals, user_location, user_country)


def make_binary_status(loads):
    format_string = '<bbbb' + ('bbf' * len(loads))

    values = [1, 0, 0, 0]  # Initial values for the first four bytes
    for load in loads:
        values.extend([
            load['status'],  # Status
            load['load'],    # Load
            load['partial_score']  # Partial score
        ])

    print(format_string, values)

    return struct.pack(format_string, *values)


@pytest.fixture
def mock_binary_status():
    return make_binary_status(LOADS)


def test_server_status_new(mock_logicals_location_country):
    logicals, user_location, user_country = mock_logicals_location_country

    proton.vpn.lib.ServerStatus(logicals, user_location, user_country)


def test_server_status_status_id(mock_logicals_location_country):
    logicals, user_location, user_country = mock_logicals_location_country

    server_status = proton.vpn.lib.ServerStatus(logicals, user_location,
                                                user_country)
    assert server_status.status_id() == STATUS_TOKEN


def test_server_status_compute_loads(mock_logicals_location_country,
                                     mock_binary_status):
    logicals, user_location, user_country = mock_logicals_location_country

    server_status = proton.vpn.lib.ServerStatus(logicals, user_location,
                                                user_country)
    loads = server_status.compute_loads(mock_binary_status)

    assert loads[0]["IsEnabled"] is True
    assert loads[0]["IsVisible"] is True
    assert loads[0]["IsAutoconnectable"] is False
    assert loads[0]["Load"] == 50
    assert abs(loads[0]["Score"] - 0.5) < 0.01
