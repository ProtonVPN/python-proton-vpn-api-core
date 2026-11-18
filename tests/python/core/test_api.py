"""
Copyright (c) 2026 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""
from types import SimpleNamespace

import pytest

from proton.vpn.core.api import ProtonVPNAPI


@pytest.mark.parametrize(
    "library_available,registered_key,expected",
    [
        (False, False, False),
        (False, True, False),
        (True, False, False),
        (True, True, True),
    ],
)
def test_supports_fido2_uses_current_session_capabilities(
        monkeypatch, library_available, registered_key, expected
):
    api = object.__new__(ProtonVPNAPI)
    api._session_holder = SimpleNamespace(
        session=SimpleNamespace(
            fido2_lib_available=library_available,
            supports_fido2=registered_key,
        )
    )

    def fail_if_deprecated_property_is_used(_api):
        pytest.fail("supports_fido2 called the deprecated capability property")

    monkeypatch.setattr(
        ProtonVPNAPI,
        "is_fido2_lib_available",
        property(fail_if_deprecated_property_is_used),
    )

    assert api.supports_fido2 is expected
