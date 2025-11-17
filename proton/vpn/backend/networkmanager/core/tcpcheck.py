"""
Utility module to do TCP connection checks.
"""
import asyncio
import ipaddress
import logging
import socket
from asyncio import as_completed
from contextlib import closing
from typing import List, Union

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5


def _get_address_family(
        ip_address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
) -> socket.AddressFamily:  # pylint: disable=no-member
    if isinstance(ip_address, ipaddress.IPv4Address):
        return socket.AF_INET
    if isinstance(ip_address, ipaddress.IPv6Address):
        return socket.AF_INET6
    raise TypeError(f"Invalid IP address: {ip_address}")


def is_port_reachable(
        ip_address: str, port: str, timeout_in_secs: int = DEFAULT_TIMEOUT
) -> bool:
    """
    Checks if the specified IP address is reachable by opening a TCP socket
    to the specified port.

    :param ip_address: IP address to connect to.
    :param port: TCP port to connect to.
    :param timeout_in_secs: Optional connection timeout.
    :returns: True if a socket could be opened to the specified address/port,
        or False otherwise.
    """
    ip_address = ipaddress.ip_address(ip_address)
    address_family = _get_address_family(ip_address)

    logger.debug("Checking %s:%s...", ip_address, port)
    with closing(socket.socket(address_family, socket.SOCK_STREAM)) as sock:
        sock.settimeout(timeout_in_secs)
        socket_result = sock.connect_ex((f"{ip_address}", port))
        logger.debug("%s:%s => %s", ip_address, port, socket_result)
        return socket_result == 0


async def is_any_port_reachable(
        ip_address: str, ports: List[str], timeout: int = DEFAULT_TIMEOUT
) -> bool:
    """
    Checks if the specified IP address is reachable by opening a TCP socket
    to any of the specified ports.

    All ports are probed in parallel. As soon as a socket is opened to
    one of them, connectivity is reported by returning True. If all
    the connections to the different ports fail, then False is returned.

    :param ip_address: IP address to connect to.
    :param port: TCP ports to try to connect to.
    :param timeout_in_secs: Optional connection timeout.
    :returns: True if a socket could be opened to the specified address/ports,
        or False otherwise.
    """
    loop = asyncio.get_running_loop()

    async def _is_port_reachable(port):
        return await loop.run_in_executor(None, is_port_reachable, ip_address, port, timeout)

    tasks = [
        asyncio.create_task(_is_port_reachable(port))
        for port in ports
    ]
    for task in as_completed(tasks):
        try:
            return await task
        except Exception:  # pylint: disable=broad-except
            return False
