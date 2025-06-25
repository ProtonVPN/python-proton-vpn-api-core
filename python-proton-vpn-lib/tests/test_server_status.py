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
def mock_location_logicals():
    location = {
        "Country": "FR",
        "Lat": 35.65,
        "Long": 139.83
    }
    logicals = {
        "Status": STATUS_TOKEN,
        "LogicalServers": [
            {
                "Status": {
                    "Index": 0,
                    "Penalty": 0,
                    "Cost": 1,
                },
                "Domain": "se-jp-01.protonvpn.net",
                "EntryCountry": "FR",
                "ExitCountry": "FR",
                "ID": "jfskjfsdkfjksdnvknsvskdjv",
                "Location": {
                    "Lat": 35.65,
                    "Long": 139.83
                },
                "Name": "SE-JP#1",
                "Servers": [
                    {
                        "Domain": "node-jp-14.protonvpn.net",
                    },
                ]
            }
        ]
    }

    return (location, logicals)


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


def test_server_status_new(mock_location_logicals):
    location, logicals = mock_location_logicals

    proton.vpn.lib.ServerStatus(logicals, location)


def test_server_status_status_id(mock_location_logicals):
    location, logicals = mock_location_logicals

    server_status = proton.vpn.lib.ServerStatus(logicals, location)
    assert server_status.status_id() == STATUS_TOKEN


def test_server_status_compute_loads(mock_location_logicals,
                                     mock_binary_status):
    location, logicals = mock_location_logicals

    server_status = proton.vpn.lib.ServerStatus(logicals, location)
    loads = server_status.compute_loads(mock_binary_status)
    assert loads[0] == {'ID': '', 'Status': 3, 'Load': 50, 'Score': 0.5}


def test_server_status_read_status(mock_location_logicals,
                                   mock_binary_status):
    location, logicals = mock_location_logicals

    server_status = proton.vpn.lib.ServerStatus(logicals, location)
    loads = server_status.read_status(mock_binary_status)
    assert loads == LOADS
