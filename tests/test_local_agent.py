from proton.vpn.core.local_agent.fallback_local_agent import PROTON_VPN_ROOT_CERT
from proton.vpn.core.session.certificates import Certificate


def test_proton_vpn_root_certificate_is_not_close_to_expiration():
    """
    If this test fails then we need to request a new Proton VPN root
    certificate and hardcode it again.
    """
    cert = Certificate(cert_pem=PROTON_VPN_ROOT_CERT)
    ninety_days_in_seconds = 90 * 24 * 60 * 60
    assert cert.validity_period > ninety_days_in_seconds
