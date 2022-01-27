class VPNConnectionController:
    def __init__(self, vpnconnection_factory=None):
        self._current_connection = None
        _vpnconn_factory = vpnconnection_factory

        if not _vpnconn_factory:
            from protonvpn.vpnconnection import VPNConnection
            _vpnconn_factory = VPNConnection

        self._vpnconnection_factory = _vpnconn_factory

    def setup(self, protocol, backend=None):
        _protocol = "openvpn_udp"

        if "openvpn" in protocol.lower() and "tcp" in protocol.lower():
            _protocol = "openvpn_tcp"
        elif "ikev2" in protocol.lower():
            _protocol = "ikev2"
        elif "wg" in protocol.lower() or "wireguard" in protocol.lower():
            _protocol = "wireguard"

        self._current_connection = self._vpnconnection_factory.get_from_factory(
            _protocol, backend
        )

    def connect(self, vpnserver, vpncredentials, settings):
        self._current_connection = self._current_connection(
            vpnserver, vpncredentials, settings
        )
        self._current_connection.up()

    def disconnect(self):
        if not self._current_connection:
            self._current_connection = self._vpnconnection_factory.get_current_connection()

        self._current_connection.down()

    def _connection_status_update(self, status):
        pass
