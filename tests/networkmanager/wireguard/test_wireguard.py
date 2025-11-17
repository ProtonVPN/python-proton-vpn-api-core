import os

import pytest
from proton.vpn.backend.networkmanager.protocol.wireguard.wireguard import FWMARK_ENV_VAR, get_fwmark_from_env_var


def test_get_fwmark_from_env_var_returns_env_var_value_if_available_and_valid():
    os.environ[FWMARK_ENV_VAR] = "51821"
    assert get_fwmark_from_env_var() == 51821


@pytest.mark.parametrize(
        "env_var_value", [
            "51820",  # too small
            str(2**32),  # too big
            "#!!?"  # invalid int,
        ]
)
def test_get_fwmark_from_env_var_returns_None_if_env_var_contains_invalid_value(env_var_value):
    os.environ[FWMARK_ENV_VAR] = env_var_value
    assert get_fwmark_from_env_var() is None