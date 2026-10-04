# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/error.py
#   scapy 2.7.0
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Copyright (C) the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — the loggers and exception classes under scapy's names; the
#                formatter does not colour, since wiry has no colour themes.

"""The exception classes and loggers scapy scripts catch and configure."""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Tuple

__all__ = [
    "Scapy_Exception", "ScapyInvalidPlatformException",
    "ScapyNoDstMacException", "ScapyFreqFilter", "ScapyColoredFormatter",
    "log_scapy", "log_runtime", "log_interactive", "log_loading", "warning",
]


class Scapy_Exception(Exception):
    pass


class ScapyInvalidPlatformException(Scapy_Exception):
    pass


class ScapyNoDstMacException(Scapy_Exception):
    pass


class ScapyFreqFilter(logging.Filter):
    """Lets a warning from one call site through twice per
    ``conf.warning_threshold`` seconds, the second time prefixed "more"."""

    def __init__(self) -> None:
        logging.Filter.__init__(self)
        self.warning_table: Dict[int, Tuple[float, int]] = {}

    def filter(self, record: logging.LogRecord) -> bool:
        import traceback
        from .capture import conf

        if record.levelno <= logging.INFO:
            return True
        wt = conf.warning_threshold
        if wt > 0:
            caller = 0
            for _, line, name, _ in traceback.extract_stack():
                if name == "warning":
                    break
                caller = line
            tm, nb = self.warning_table.get(caller, (0, 0))
            now = time.time()
            if now - tm > wt:
                tm, nb = now, 0
            elif nb < 2:
                nb += 1
                if nb == 2:
                    record.msg = "more " + str(record.msg)
            else:
                return False
            self.warning_table[caller] = (tm, nb)
        return True


class ScapyColoredFormatter(logging.Formatter):
    levels_colored = {
        "DEBUG": "reset",
        "INFO": "reset",
        "WARNING": "bold+yellow",
        "ERROR": "bold+red",
        "CRITICAL": "bold+white+bg_red",
    }


log_scapy = logging.getLogger("wiry")
log_scapy.propagate = False
if log_scapy.level == logging.NOTSET:
    log_scapy.setLevel(logging.WARNING)
if not log_scapy.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(ScapyColoredFormatter("%(levelname)s: %(message)s"))
    log_scapy.addHandler(_handler)
log_runtime = logging.getLogger("wiry.runtime")
log_runtime.addFilter(ScapyFreqFilter())
log_interactive = logging.getLogger("wiry.interactive")
log_interactive.setLevel(logging.DEBUG)
log_loading = logging.getLogger("wiry.loading")


def warning(x: Any, *args: Any, **kargs: Any) -> None:
    log_runtime.warning(x, *args, **kargs)
