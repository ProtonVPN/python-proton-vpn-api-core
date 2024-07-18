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
import copy
import os
import pytest
from types import SimpleNamespace
import tempfile
import json

from proton.vpn.core.session_holder import ClientTypeMetadata
from proton.vpn.core.usage import UsageReporting

SECRET_FILE = "secret.txt"
SECRET_PATH = os.path.join("/home/wozniak/5nkfiudfmk/.cache", SECRET_FILE)
MACHINE_ID = "bg77t2rmpjhgt9zim5gkz4t78jfur39f"
SENTRY_USER_ID = "70cf75689cecae78ec588316320d76477c71031f7fd172dd5577ac95934d4499"
USERNAME = "tester"

EVENT_TO_SEND = {
    "frames": [
        {
            "filename": "/home/tester/src/quick_connect_widget.py",
            "abs_path": "/home/tester/src/quick_connect_widget.py",
            "function": "_on_disconnect_button_clicked",
            "module": "proton.vpn.app.gtk.widgets.vpn.quick_connect_widget",
            "lineno": 102,
            "pre_context": [
                "        future = self._controller.connect_to_fastest_server()",
                "        future.add_done_callback(lambda f: GLib.idle_add(f.result))  # bubble up exceptions if any.",
                "",
                "    def _on_disconnect_button_clicked(self, _):",
                "        logger.info(\"Disconnect from VPN\", category=\"ui\", event=\"disconnect\")"
            ],
            "context_line": "        future = self._controller.disconnect()",
            "post_context": [
                "        future.add_done_callback(lambda f: GLib.idle_add(f.result))  # bubble up exceptions if any."
            ],
            "vars": {
                "self": "<quick_connect_widget.... (proton+... at 0x601b5e322d90)>",
                "_": "<Gtk.Button object at 0x7f83d4aa8140 (GtkButton at 0x601b5e37ea40)>"
            },
            "in_app": True
        },
        {
            "filename": "/home/tester/src/ProtonVPN/linux/proton-vpn-gtk-app/proton/vpn/app/gtk/controller.py",
            "abs_path": "/home/tester/src/ProtonVPN/linux/proton-vpn-gtk-app/proton/vpn/app/gtk/controller.py",
            "function": "disconnect",
            "module": "proton.vpn.app.gtk.controller",
            "lineno": 224,
            "pre_context": [
                "        :return: A Future object that resolves once the connection reaches the",
                "        \"disconnected\" state.",
                "        \"\"\"",
                "        error = FileNotFoundError(\"This method is not implemented\")",
                "        error.filename = \"/home/wozniak/randomfile.py\""
            ],
            "context_line": "        raise error",
            "post_context": [
                "",
                "        return self.executor.submit(self._connector.disconnect)",
                "",
                "    @property",
                "    def account_name(self) -> str:"
            ],
            "vars": {
                "self": "<proton.vpn.app.gtk.controller.Controller object at 0x7f83e1856da0>",
                "error": "FileNotFoundError('This method is not implemented')"
            },
            "in_app": True
        }
    ]
}

@pytest.mark.parametrize("enabled", [True, False])
def test_usage_report_enabled(enabled):
    report_error = SimpleNamespace(invoked=False)

    usage_reporting = UsageReporting(ClientTypeMetadata("test_usage.py", "none"))

    def capture_exception(error):
        report_error.invoked = True

    usage_reporting.enabled = enabled
    usage_reporting._capture_exception = capture_exception

    EMPTY_ERROR = None
    usage_reporting.report_error(EMPTY_ERROR)

    assert report_error.invoked == enabled, "UsageReporting enable state does not match the error reporting"


def test_sanitize_event():

    event = copy.deepcopy(EVENT_TO_SEND)

    UsageReporting._sanitize_event(event, None, "tester")

    assert USERNAME in json.dumps(EVENT_TO_SEND), "Username should be in the event"
    assert USERNAME not in json.dumps(event), "Username should not be in the event"


def test_userid_calaculation():
    with tempfile.NamedTemporaryFile() as file:
        file.write(MACHINE_ID.encode('utf-8'))
        file.seek(0)

        assert UsageReporting._get_user_id(
            machine_id_filepath=file.name,
            user_name=USERNAME) == SENTRY_USER_ID, "Error hashing does not match the expected value"
