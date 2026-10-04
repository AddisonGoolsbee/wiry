"""scapy's ``scapy.pton_ntop``, which scripts import the converters from."""

from .compat import _inet6_ntop, _inet6_pton, inet_ntop, inet_pton

__all__ = ["inet_pton", "inet_ntop", "_inet6_pton", "_inet6_ntop"]
