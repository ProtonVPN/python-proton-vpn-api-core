"""
Bug Report feature module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List
import typing
import distro

VPN_CLIENT_TYPE = "2"  # 1: email;  2: VPN


@dataclass
class BugReportForm:  # pylint: disable=too-many-instance-attributes
    """Bug report form data to be submitted to customer support."""
    username: str
    email: str
    title: str
    description: str
    client_version: str
    client: str
    attachments: List[typing.IO] = field(default_factory=list)
    os: str = distro.id()  # pylint: disable=invalid-name
    os_version: str = distro.version()
    client_type: str = VPN_CLIENT_TYPE
