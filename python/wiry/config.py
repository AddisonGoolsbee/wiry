# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/config.py
#   scapy 2.7.0
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Copyright (C) the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — the module-level helpers only; the configuration object
#                itself is wiry.capture's ``conf``.
#   2026-10-04 — CacheInstance and NetCache, for ``conf.netcache``.

"""``conf``, under the module name scapy scripts import it from, and the
helpers that sit beside it."""

from __future__ import annotations

import atexit
import functools
import os
import platform
import shutil
import time
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from . import __version__ as VERSION
from .capture import _Conf as Conf
from .capture import conf

__all__ = [
    "conf", "Conf", "VERSION", "isPyPy", "isCryptographyValid", "isCryptographyAdvanced",
    "isCryptographyBackendCompatible", "crypto_validator",
    "scapy_delete_temp_files", "CacheInstance", "NetCache",
]


def isPyPy() -> bool:
    return platform.python_implementation() == "PyPy"


def _version_checker(module: Any, minver: tuple) -> bool:
    version = getattr(module, "__version__", "")
    parts = []
    for p in version.split(".")[:3]:
        digits = "".join(c for c in p if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) >= minver


def isCryptographyValid() -> bool:
    """Whether ``cryptography`` 2.0 or later is installed; nothing in wiry
    needs it, but scripts that do ask this way."""
    try:
        import cryptography
    except ImportError:
        return False
    return _version_checker(cryptography, (2, 0, 0))


def isCryptographyAdvanced() -> bool:
    """Whether ``cryptography`` can do X25519."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        X25519PrivateKey.generate()
    except Exception:
        return False
    return True


def isCryptographyBackendCompatible() -> bool:
    try:
        import cryptography
    except ImportError:
        return False
    return _version_checker(cryptography, (2, 0, 0))


def crypto_validator(func: Callable) -> Callable:
    """Refuse to call ``func`` without ``cryptography``, naming the fix."""
    @functools.wraps(func)
    def func_in(*args: Any, **kwargs: Any) -> Any:
        if not isCryptographyValid():
            raise ImportError(
                "Cannot execute crypto-related method! Please install "
                "python-cryptography v1.7 or later."
            )
        return func(*args, **kwargs)
    return func_in


@atexit.register
def scapy_delete_temp_files() -> None:
    """Remove what ``get_temp_file`` and ``get_temp_dir`` made, unless asked
    to keep it."""
    for f in conf.temp_files:
        try:
            if os.path.isdir(f):
                shutil.rmtree(f)
            else:
                os.unlink(f)
        except OSError:
            pass
    del conf.temp_files[:]


class CacheInstance(Dict[str, Any]):
    """A dict whose entries expire ``timeout`` seconds after they were set."""

    __slots__ = ["timeout", "name", "_timetable"]

    def __init__(self, name: str = "noname", timeout: Optional[int] = None):
        self.timeout = timeout
        self.name = name
        self._timetable: Dict[str, float] = {}

    def flush(self) -> None:
        self._timetable.clear()
        self.clear()

    def __getitem__(self, item: Any) -> Any:
        if item in self.__slots__:
            return object.__getattribute__(self, item)
        if not self.__contains__(item):
            raise KeyError(item)
        return super().__getitem__(item)

    def __contains__(self, item: Any) -> bool:
        if not super().__contains__(item):
            return False
        if self.timeout is not None:
            if time.time() - self._timetable[item] > self.timeout:
                return False
        return True

    def get(self, item: Any, default: Any = None) -> Any:
        try:
            return self[item]
        except KeyError:
            return default

    def __setitem__(self, item: Any, v: Any) -> None:
        if item in self.__slots__:
            return object.__setattr__(self, item, v)
        self._timetable[item] = time.time()
        super().__setitem__(item, v)

    def update(self, other: Any, **kwargs: Any) -> None:
        """Take each entry of ``other`` that is missing here or newer there."""
        for key, value in other.items():
            if key not in self or self._timetable[key] < other._timetable[key]:
                dict.__setitem__(self, key, value)
                self._timetable[key] = other._timetable[key]

    def iteritems(self) -> Iterator[Tuple[Any, Any]]:
        if self.timeout is None:
            return iter(super().items())
        t0 = time.time()
        return ((k, v) for (k, v) in super().items()
                if t0 - self._timetable[k] < self.timeout)

    def iterkeys(self) -> Iterator[Any]:
        if self.timeout is None:
            return iter(super().keys())
        t0 = time.time()
        return (k for k in super().keys() if t0 - self._timetable[k] < self.timeout)

    def __iter__(self) -> Iterator[Any]:
        return self.iterkeys()

    def itervalues(self) -> Iterator[Any]:
        return (v for _, v in self.iteritems())

    def items(self) -> Any:
        return list(self.iteritems())

    def keys(self) -> Any:
        return list(self.iterkeys())

    def values(self) -> Any:
        return list(self.itervalues())

    def __len__(self) -> int:
        if self.timeout is None:
            return super().__len__()
        return len(self.keys())

    def summary(self) -> str:
        return "%s: %i valid items. Timeout=%rs" % (self.name, len(self), self.timeout)

    def __repr__(self) -> str:
        s = []
        if self:
            mk = max(len(k) for k in self)
            fmt = "%%-%is %%s" % (mk + 1)
            for item in self.items():
                s.append(fmt % item)
        return "\n".join(s)

    def copy(self) -> "CacheInstance":
        import copy
        return copy.copy(self)


class NetCache:
    """The named caches resolvers share, each an attribute: ``dns_cache``."""

    def __init__(self) -> None:
        self._caches_list: List[CacheInstance] = []

    def add_cache(self, cache: CacheInstance) -> None:
        self._caches_list.append(cache)
        setattr(self, cache.name, cache)

    def new_cache(self, name: str, timeout: Optional[int] = None) -> CacheInstance:
        c = CacheInstance(name=name, timeout=timeout)
        self.add_cache(c)
        return c

    def __delattr__(self, attr: str) -> None:
        raise AttributeError("Cannot delete attributes")

    def update(self, other: "NetCache") -> None:
        for co in other._caches_list:
            if hasattr(self, co.name):
                getattr(self, co.name).update(co)
            else:
                self.add_cache(co.copy())

    def flush(self) -> None:
        for c in self._caches_list:
            c.flush()

    def __repr__(self) -> str:
        return "\n".join(c.summary() for c in self._caches_list)
