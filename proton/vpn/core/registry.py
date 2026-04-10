"""
Registry for modular components of the VPN API.

Any type can be registered as long as it implements the `Entry` protocol, the
type can then be retrived by its key or by iterating over the available
implementations.

This is a simpler and more dynamic alternative to using entry points.

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
import importlib

from abc import abstractmethod
from typing import Iterator, Optional, Protocol


class Entry(Protocol):  # pylint: disable=R0903
    """
    Registry entries must implement this protocol.
    """
    @classmethod
    @abstractmethod
    def get_key(cls) -> str:
        """
        Type name the implementation will be registered under.

        To be implemented by subclasses.

        :return: The type name the implementation will be registered under.
        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def get_priority(cls) -> int:
        """
        Priority of the implementation.

        To be implemented by subclasses.

        :return: The priority of the implementation.
            Lower values indicate higher priority.
        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def validate(cls) -> bool:
        """
        Determines whether the implementation is valid or not.
        To be implemented by subclasses.

        If this method returns `False` then the implementation
        will be skipped.

        :return: `True` if the implementation is valid or `False` otherwise.
        """
        raise NotImplementedError


class Registry:
    """
    Registry of implementations.

    This class is used to keep track of the available implementations.
    """

    def __init__(self):
        self._registry = {}

    def register(self, entry_type: type[Entry]):
        """Registers an implementation."""

        self._registry[entry_type.get_key()] = entry_type  # pylint: disable=W0212

    def register_from_registrars(self, registrars):
        """Registers implementations by calling each registrar with this registry."""
        for registrar in registrars:
            registrar(self)

    def register_from_module(self, module: str):
        """
        Registers implementations under the given root module.
        """
        self.register_from_registrars(
            # pylint: disable-next=line-too-long
            [importlib.import_module(module).register]  # noqa: E501 # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
        )

    def get(self, key: str) -> Optional[type[Entry]]:
        """
        Returns the implementation for the given key.

        If there's no valid implementation for the given key, it returns None.
        """
        if entry := self._registry.get(key, None):
            if entry.validate():
                return entry

        raise RuntimeError(f"No valid implementation found for {key}")

    def iter(self, interface: type) -> Iterator[type[Entry]]:
        """
        Returns an iterator over the available entries ordered by
        priority and filtered by validity.
        """
        def validate_and_priority(cls):
            return (
                issubclass(cls, interface)
                and cls.validate()  # pylint: disable=W0212
                and cls.get_priority() is not None  # pylint: disable=W0212
            )

        def priority(cls):
            return cls.get_priority()  # pylint: disable=W0212

        return iter(
            sorted(
                filter(
                    validate_and_priority,
                    self._registry.values(),
                ),
                key=priority
            )
        )
