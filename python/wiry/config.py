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

"""``conf``, under the module name scapy scripts import it from, and the
helpers that sit beside it."""

from __future__ import annotations

import atexit
import functools
import os
import platform
import shutil
from typing import Any, Callable

from . import __version__ as VERSION
from .capture import _Conf as Conf
from .capture import conf

__all__ = [
    "conf", "Conf", "VERSION", "isPyPy", "isCryptographyValid", "isCryptographyAdvanced",
    "isCryptographyBackendCompatible", "crypto_validator",
    "scapy_delete_temp_files",
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
