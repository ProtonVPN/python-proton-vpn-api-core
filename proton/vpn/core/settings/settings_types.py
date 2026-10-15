"""
Copyright (c) 2026 Proton AG

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

The building block of settings classes

Settings are sparse: a node only holds the values that were explicitly set,
and anything unset resolves to its default when read. This is what lets
`to_dict` persist only what the user chose. This module contains:

- `Setting`: a leaf setting, such as a bool or a string. It stores `None` while
  unset, and reading it then returns its default. A node can override that
  default with `Setting.set_default`, for instance to make it depend on the
  user tier.
- `Group`: a branch setting, which always holds a real settings node, for
  instance the custom DNS settings of the general settings.
- `settings`: a class decorator that builds the constructor of a settings
  class from its `Setting` and `Group` attributes.

For example::

    @settings
    class Features:
        moderate_nat = Setting[bool](default=False)
        split_tunneling = Group[SplitTunneling]()

    Features(moderate_nat=None, split_tunneling=SplitTunneling.from_dict(None))
"""
from __future__ import annotations

from typing import Any, Generic, Hashable, Optional, TypeVar

# Hashable so that no mutable value (a list, say) is stored: use a tuple.
S = TypeVar("S", bound=Hashable)
G = TypeVar("G")


class Setting(Generic[S]):
    """A leaf setting.

    The owning settings group stores ``None`` while the setting is unset.
    Reading an unset setting returns the default given to ``set_default`` for
    that settings group, or ``initial_default`` if there is none.
    """

    def __init__(self, *, default: S):
        self.initial_default = default
        self.attr_name = ""
        self.default_name = ""

    def __set_name__(self, owner, name):
        self.attr_name = f"_setting_{name}"
        self.default_name = f"_setting_default_{name}"

    def __get__(self, settings_group: Any, owner=None) -> S:

        # Invoked as a static method
        if settings_group is None:
            return self  # type: ignore[return-value]

        # Get the setting value
        value = getattr(settings_group, self.attr_name)
        if value is not None:
            return value

        # Get the default value
        default = getattr(settings_group, self.default_name, None)
        if default is not None:
            return default

        # Get the initial default value
        return self.initial_default

    def __set__(self, settings_group: Any, value: Optional[S]) -> None:
        self._set(settings_group, value)

    def _set(self, settings_group: Any, value: Optional[S]) -> None:
        """Stores the value in the settings group."""
        setattr(settings_group, self.attr_name, value)

    def is_set(self, settings_group: Any) -> bool:
        """Whether the settings group holds an explicit value, rather than the
        default."""
        return getattr(settings_group, self.attr_name) is not None

    def set_default(self, settings_group: Any, default: S) -> None:
        """Sets the default value for this setting (on this settings group)"""
        setattr(settings_group, self.default_name, default)


class Group(Generic[G]):
    """A branch setting: always a stored node of type ``G``, never ``None``.

    The slot is read-only after construction: change the node's own settings.
    """

    def __init__(self):
        self.attr_name = ""

    def __set_name__(self, owner, name):
        self.attr_name = f"_{name}"

    def __get__(self, settings_group: Any, owner=None) -> G:
        if settings_group is None:
            # Class access returns the descriptor itself.
            return self  # type: ignore[return-value]

        # Always the stored object.
        return getattr(settings_group, self.attr_name)

    def __set__(self, settings_group: Any, value: G) -> None:
        raise AttributeError(
            f"{self.attr_name[1:]} is read-only, set it at construction")

    def _set(self, settings_group: Any, value: G) -> None:
        """Stores the group in a settings group under construction."""
        setattr(settings_group, self.attr_name, value)


def settings(cls):
    """Gives ``cls`` a constructor taking each of its ``Setting`` and
    ``Group`` attributes as a required keyword argument. Pass ``None`` for
    a setting that is unset."""
    descriptors = {
        name: value for name, value in vars(cls).items()
        if isinstance(value, (Setting, Group))
    }
    names = descriptors.keys()

    def __init__(self, **kwargs):
        if unknown := kwargs.keys() - names:
            raise TypeError(
                f"{cls.__name__} got unknown settings: {sorted(unknown)}")

        for name, descriptor in descriptors.items():
            # pylint: disable-next=protected-access
            descriptor._set(self, kwargs[name])

    cls.__init__ = __init__
    return cls
