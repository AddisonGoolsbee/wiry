# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/data.py and scapy/dadict.py
#   scapy 2.7.0
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#
# Changed by the wiry authors:
#   2026-10-03 — merged the two modules, made the databases load on first
#                touch rather than at import, and dropped the on-disk pickle
#                cache.

"""Constants and the name databases: protocols, services, EtherTypes, OUIs.

The databases are read from the host's own files where it has them and from
the copies in ``wiry.libs`` where it does not, exactly as scapy does, so a
name can differ between hosts. Each one loads on first touch: ``import wiry``
reads this module for its names and must not parse /etc or decompress the OUI
list to do it.
"""

from __future__ import annotations

import calendar
import os
import sys
import warnings
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Union

from .error import Scapy_Exception, log_loading

_WINDOWS = sys.platform.startswith("win")
_OPENBSD = sys.platform.startswith("openbsd")
_FREEBSD = "freebsd" in sys.platform
_NETBSD = sys.platform.startswith("netbsd")


def fixname(x: Union[bytes, str]) -> str:
    """``x`` made usable as an attribute name."""
    if isinstance(x, bytes):
        x = x.decode(errors="backslashreplace")
    x = str(x)
    if x and x[0] in "0123456789":
        x = "n_" + x
    return x.translate(
        "________________________________________________"
        "0123456789_______ABCDEFGHIJKLMNOPQRSTUVWXYZ______"
        "abcdefghijklmnopqrstuvwxyz____________________________"
        "______________________________________________________"
        "___________________________________________________"
    )


class DADict_Exception(Scapy_Exception):
    pass


class DADict:
    """A dict whose keys are also reachable as attributes named by their
    values: ``ETHER_TYPES[2048]`` is ``"IPv4"`` and ``ETHER_TYPES.IPv4`` is
    2048."""

    __slots__ = ["_name", "d"]

    def __init__(self, _name: str = "DADict", **kargs: Any):
        self._name = _name
        self.d: Dict[Any, Any] = {}
        self.update(kargs)

    def __class_getitem__(cls, item: Any) -> type:
        return cls

    def ident(self, v: Any) -> str:
        if isinstance(v, (str, bytes)):
            return fixname(v)
        return "unknown"

    def update(self, *args: Any, **kwargs: Any) -> None:
        for k, v in dict(*args, **kwargs).items():
            self[k] = v

    def iterkeys(self) -> Iterator[Any]:
        for x in self.d:
            if not isinstance(x, str) or x[0] != "_":
                yield x

    def keys(self) -> List[Any]:
        return list(self.iterkeys())

    def __iter__(self) -> Iterator[Any]:
        return self.iterkeys()

    def itervalues(self) -> Iterator[Any]:
        return iter(self.d.values())

    def values(self) -> List[Any]:
        return list(self.itervalues())

    def items(self) -> List[Tuple[Any, Any]]:
        return [(k, self.d[k]) for k in self.iterkeys()]

    def get(self, key: Any, default: Any = None) -> Any:
        return self.d.get(key, default)

    def __contains__(self, key: Any) -> bool:
        return key in self.d

    def _show(self) -> None:
        for k in self.iterkeys():
            print("%10s = %r" % (k, self[k]))

    def __repr__(self) -> str:
        return "<%s - %s elements>" % (self._name, len(self))

    def __getitem__(self, attr: Any) -> Any:
        return self.d[attr]

    def __setitem__(self, attr: Any, val: Any) -> None:
        self.d[attr] = val

    def __len__(self) -> int:
        return len(self.d)

    def __bool__(self) -> bool:
        # scapy answers len > 1, from when the name was stored as an entry; it
        # no longer is, so a one-entry table read as empty there.
        return len(self) > 0

    def __getattr__(self, attr: str) -> Any:
        try:
            return object.__getattribute__(self, attr)
        except AttributeError:
            if not attr.startswith("__"):
                for k, v in self.d.items():
                    if self.ident(v) == attr:
                        return k
        raise AttributeError(attr)

    def __dir__(self) -> List[str]:
        return [self.ident(x) for x in self.itervalues()]

    def __reduce__(self) -> Tuple:
        return (self.__class__, (self._name,), (self.d,))

    def __setstate__(self, state: Tuple) -> "DADict":
        self.d.update(state[0])
        return self


ETHER_ANY = b"\x00" * 6
ETHER_BROADCAST = b"\xff" * 6

# bits/socket.h and asm/socket.h
SOL_PACKET = 263
SO_ATTACH_FILTER = 26
SO_TIMESTAMPNS = 35

ETH_P_ALL = 3
ETH_P_IP = 0x800
ETH_P_ARP = 0x806
ETH_P_IPV6 = 0x86DD
ETH_P_MACSEC = 0x88E5

# net/if_arp.h
ARPHDR_ETHER = 1
ARPHDR_METRICOM = 23
ARPHDR_PPP = 512
ARPHDR_LOOPBACK = 772
ARPHDR_TUN = 65534

# pcap/dlt.h; the BSDs number a few of these their own way.
DLT_NULL = 0
DLT_EN10MB = 1
DLT_EN3MB = 2
DLT_AX25 = 3
DLT_PRONET = 4
DLT_CHAOS = 5
DLT_IEEE802 = 6
DLT_ARCNET = 7
DLT_SLIP = 8
DLT_PPP = 9
DLT_FDDI = 10
DLT_RAW = 14 if _OPENBSD else 12
DLT_RAW_ALT = 101
if _FREEBSD or _NETBSD:
    DLT_SLIP_BSDOS = 13
    DLT_PPP_BSDOS = 14
else:
    DLT_SLIP_BSDOS = 15
    DLT_PPP_BSDOS = 16
if _FREEBSD:
    DLT_PFSYNC = 121
else:
    DLT_PFSYNC = 18
    DLT_HHDLC = 121
DLT_ATM_CLIP = 19
DLT_PPP_SERIAL = 50
DLT_PPP_ETHER = 51
DLT_SYMANTEC_FIREWALL = 99
DLT_C_HDLC = 104
DLT_IEEE802_11 = 105
DLT_FRELAY = 107
if _OPENBSD:
    DLT_LOOP = 12
    DLT_ENC = 13
else:
    DLT_LOOP = 108
    DLT_ENC = 109
DLT_LINUX_SLL = 113
DLT_LTALK = 114
DLT_PFLOG = 117
DLT_PRISM_HEADER = 119
DLT_AIRONET_HEADER = 120
DLT_IP_OVER_FC = 122
DLT_IEEE802_11_RADIO = 127
DLT_ARCNET_LINUX = 129
DLT_LINUX_IRDA = 144
DLT_IEEE802_11_RADIO_AVS = 163
DLT_LINUX_LAPD = 177
DLT_BLUETOOTH_HCI_H4 = 187
DLT_USB_LINUX = 189
DLT_PPI = 192
DLT_IEEE802_15_4_WITHFCS = 195
DLT_BLUETOOTH_HCI_H4_WITH_PHDR = 201
DLT_AX25_KISS = 202
DLT_PPP_WITH_DIR = 204
DLT_FC_2 = 224
DLT_CAN_SOCKETCAN = 227
if _OPENBSD:
    DLT_IPV4 = DLT_RAW
    DLT_IPV6 = DLT_RAW
else:
    DLT_IPV4 = 228
    DLT_IPV6 = 229
DLT_IEEE802_15_4_NOFCS = 230
DLT_USBPCAP = 249
DLT_NETLINK = 253
DLT_USB_DARWIN = 266
DLT_BLUETOOTH_LE_LL = 251
DLT_BLUETOOTH_LINUX_MONITOR = 254
DLT_BLUETOOTH_LE_LL_WITH_PHDR = 256
DLT_VSOCK = 271
DLT_NORDIC_BLE = 272
DLT_ETHERNET_MPACKET = 274
DLT_LINUX_SLL2 = 276

# Linux net/ipv6.h, plus scapy's 6to4 and unspecified bits.
IPV6_ADDR_UNICAST = 0x01
IPV6_ADDR_MULTICAST = 0x02
IPV6_ADDR_CAST_MASK = 0x0F
IPV6_ADDR_LOOPBACK = 0x10
IPV6_ADDR_GLOBAL = 0x00
IPV6_ADDR_LINKLOCAL = 0x20
IPV6_ADDR_SITELOCAL = 0x40
IPV6_ADDR_SCOPE_MASK = 0xF0
IPV6_ADDR_6TO4 = 0x0100
IPV6_ADDR_UNSPECIFIED = 0x10000

# linux/if_arp.h
ARPHRD_ETHER = 1
ARPHRD_EETHER = 2
ARPHRD_AX25 = 3
ARPHRD_PRONET = 4
ARPHRD_CHAOS = 5
ARPHRD_IEEE802 = 6
ARPHRD_ARCNET = 7
ARPHRD_DLCI = 15
ARPHRD_ATM = 19
ARPHRD_METRICOM = 23
ARPHRD_SLIP = 256
ARPHRD_CSLIP = 257
ARPHRD_SLIP6 = 258
ARPHRD_CSLIP6 = 259
ARPHRD_ADAPT = 264
ARPHRD_CAN = 280
ARPHRD_PPP = 512
ARPHRD_CISCO = 513
ARPHRD_RAWHDLC = 518
ARPHRD_TUNNEL = 768
ARPHRD_FRAD = 770
ARPHRD_LOOPBACK = 772
ARPHRD_LOCALTLK = 773
ARPHRD_FDDI = 774
ARPHRD_SIT = 776
ARPHRD_FCPP = 784
ARPHRD_FCAL = 785
ARPHRD_FCPL = 786
ARPHRD_FCFABRIC = 787
ARPHRD_IRDA = 783
ARPHRD_IEEE802_TR = 800
ARPHRD_IEEE80211 = 801
ARPHRD_IEEE80211_PRISM = 802
ARPHRD_IEEE80211_RADIOTAP = 803
ARPHRD_IEEE802154 = 804
ARPHRD_NETLINK = 824
ARPHRD_VSOCKMON = 826  # pcap-linux.c
ARPHRD_LAPD = 8445  # pcap-linux.c
ARPHRD_NONE = 0xFFFE

# The link type libpcap reports for each Linux hardware type.
ARPHRD_TO_DLT = {
    ARPHRD_ETHER: DLT_EN10MB,
    ARPHRD_METRICOM: DLT_EN10MB,
    ARPHRD_LOOPBACK: DLT_EN10MB,
    ARPHRD_EETHER: DLT_EN3MB,
    ARPHRD_AX25: DLT_AX25_KISS,
    ARPHRD_PRONET: DLT_PRONET,
    ARPHRD_CHAOS: DLT_CHAOS,
    ARPHRD_CAN: DLT_LINUX_SLL,
    ARPHRD_IEEE802_TR: DLT_IEEE802,
    ARPHRD_IEEE802: DLT_EN10MB,
    ARPHRD_ARCNET: DLT_ARCNET_LINUX,
    ARPHRD_FDDI: DLT_FDDI,
    ARPHRD_ATM: -1,
    ARPHRD_IEEE80211: DLT_IEEE802_11,
    ARPHRD_IEEE80211_PRISM: DLT_PRISM_HEADER,
    ARPHRD_IEEE80211_RADIOTAP: DLT_IEEE802_11_RADIO,
    ARPHRD_PPP: DLT_RAW,
    ARPHRD_CISCO: DLT_C_HDLC,
    ARPHRD_SIT: DLT_RAW,
    ARPHRD_CSLIP: DLT_RAW,
    ARPHRD_SLIP6: DLT_RAW,
    ARPHRD_CSLIP6: DLT_RAW,
    ARPHRD_ADAPT: DLT_RAW,
    ARPHRD_SLIP: DLT_RAW,
    ARPHRD_RAWHDLC: DLT_RAW,
    ARPHRD_DLCI: DLT_RAW,
    ARPHRD_FRAD: DLT_FRELAY,
    ARPHRD_LOCALTLK: DLT_LTALK,
    18: DLT_IP_OVER_FC,
    ARPHRD_FCPP: DLT_FC_2,
    ARPHRD_FCAL: DLT_FC_2,
    ARPHRD_FCPL: DLT_FC_2,
    ARPHRD_FCFABRIC: DLT_FC_2,
    ARPHRD_IRDA: DLT_LINUX_IRDA,
    ARPHRD_LAPD: DLT_LINUX_LAPD,
    ARPHRD_NONE: DLT_RAW,
    ARPHRD_IEEE802154: DLT_IEEE802_15_4_NOFCS,
    ARPHRD_NETLINK: DLT_NETLINK,
    ARPHRD_VSOCKMON: DLT_VSOCK,
}

PPI_DOT11COMMON = 2
PPI_DOT11NMAC = 3
PPI_DOT11NMACPHY = 4
PPI_SPECTRUM_MAP = 5
PPI_PROCESS_INFO = 6
PPI_CAPTURE_INFO = 7
PPI_AGGREGATION = 8
PPI_DOT3 = 9
PPI_GPS = 30002
PPI_VECTOR = 30003
PPI_SENSOR = 30004
PPI_ANTENNA = 30005
PPI_BTLE = 30006

PPI_TYPES = {
    PPI_DOT11COMMON: "dot11-common",
    PPI_DOT11NMAC: "dot11-nmac",
    PPI_DOT11NMACPHY: "dot11-nmacphy",
    PPI_SPECTRUM_MAP: "spectrum-map",
    PPI_PROCESS_INFO: "process-info",
    PPI_CAPTURE_INFO: "capture-info",
    PPI_AGGREGATION: "aggregation",
    PPI_DOT3: "dot3",
    PPI_GPS: "gps",
    PPI_VECTOR: "vector",
    PPI_SENSOR: "sensor",
    PPI_ANTENNA: "antenna",
    PPI_BTLE: "btle",
}

# Windows counts from 1970-01-02.
EPOCH = calendar.timegm((1970, 1, 2, 0, 0, 0, 3, 1, 0)) - 86400

MTU = 0xFFFF

# The common vendors only: the whole IANA registry is several megabytes.
IANA_ENTERPRISE_NUMBERS = {
    9: "ciscoSystems",
    35: "Nortel Networks",
    43: "3Com",
    311: "Microsoft",
    2636: "Juniper Networks, Inc.",
    4526: "Netgear",
    5771: "Cisco Systems, Inc.",
    5842: "Cisco Systems",
    11129: "Google, Inc",
    16885: "Nortel Networks",
}


def scapy_data_cache(name: str) -> Callable[[Callable], Callable]:
    """Accepted for scapy's signature and does nothing: scapy pickles each
    database to a cache folder, while wiry loads each one once per process,
    on first touch, and keeps no state on disk."""
    return lambda func: func


def load_protocols(filename: str,
                   _fallback: Optional[Callable[[], Iterator[str]]] = None,
                   _integer_base: int = 10, _cls: type = DADict) -> DADict:
    """``/etc/protocols`` as ``{number: name}``."""
    dct = _cls(_name=filename)

    def _process_data(fdesc: Any) -> None:
        for line in fdesc:
            try:
                shrp = line.find("#")
                if shrp >= 0:
                    line = line[:shrp]
                line = line.strip()
                if not line:
                    continue
                lt = tuple(line.split())
                if len(lt) < 2 or not lt[0]:
                    continue
                dct[int(lt[1], _integer_base)] = fixname(lt[0])
            except Exception as e:
                log_loading.info("Couldn't parse file [%s]: line [%r] (%s)",
                                 filename, line, e)

    try:
        if not filename:
            raise IOError
        with open(filename, "r", errors="backslashreplace") as fdesc:
            _process_data(fdesc)
    except IOError:
        if _fallback:
            _process_data(_fallback())
        else:
            log_loading.info("Can't open %s file", filename)
    return dct


class EtherDA(DADict):
    """Keyed by EtherType. A name used as the key is scapy's old spelling and
    still accepted, with a DeprecationWarning."""

    def __setitem__(self, attr: Any, val: Any) -> None:
        if isinstance(attr, str):
            attr, val = val, attr
            warnings.warn("ETHER_TYPES now uses the integer value as key !",
                          DeprecationWarning)
        super().__setitem__(attr, val)

    def __getitem__(self, attr: Any) -> Any:
        if isinstance(attr, str):
            warnings.warn("Please use 'ETHER_TYPES.%s'" % attr,
                          DeprecationWarning)
            return super().__getattr__(attr)
        return super().__getitem__(attr)


def load_ethertypes(filename: Optional[str] = None) -> EtherDA:
    """``/etc/ethertypes``, or the copy bundled from OpenBSD's."""
    def _fallback() -> Iterator[str]:
        from .libs.ethertypes import DATA
        return iter(DATA.split("\n"))

    return load_protocols(filename or "scapy/ethertypes", _fallback=_fallback,
                          _integer_base=16, _cls=EtherDA)


def load_services(filename: str) -> Tuple[DADict, DADict, DADict]:
    """``/etc/services`` as three ``{port: name}`` tables: TCP, UDP, SCTP."""
    tdct = DADict(_name="%s-tcp" % filename)
    udct = DADict(_name="%s-udp" % filename)
    sdct = DADict(_name="%s-sctp" % filename)
    dcts = {b"tcp": tdct, b"udp": udct, b"sctp": sdct}
    try:
        with open(filename, "rb") as fdesc:
            for line in fdesc:
                try:
                    shrp = line.find(b"#")
                    if shrp >= 0:
                        line = line[:shrp]
                    line = line.strip()
                    if not line:
                        continue
                    lt = tuple(line.split())
                    if len(lt) < 2 or not lt[0] or b"/" not in lt[1]:
                        continue
                    port, proto = lt[1].split(b"/", 1)
                    dtct = dcts.get(proto)
                    if dtct is None:
                        continue
                    name = fixname(lt[0])
                    if b"-" in port:
                        sport, eport = port.split(b"-")
                        for i in range(int(sport), int(eport) + 1):
                            dtct[i] = name
                    else:
                        dtct[int(port)] = name
                except Exception as e:
                    log_loading.warning(
                        "Couldn't parse file [%s]: line [%r] (%s)",
                        filename, line, e)
    except IOError:
        log_loading.info("Can't open /etc/services file")
    return tdct, udct, sdct


class ManufDA(DADict):
    """OUI -> (short name, long name)."""

    def ident(self, v: Any) -> str:
        return fixname(v[0] if isinstance(v, tuple) else v)

    def _get_manuf_couple(self, mac: str) -> Tuple[str, str]:
        oui = ":".join(mac.split(":")[:3]).upper()
        return self.d.get(oui, (mac, mac))

    def _get_manuf(self, mac: str) -> str:
        return self._get_manuf_couple(mac)[1]

    def _get_short_manuf(self, mac: str) -> str:
        return self._get_manuf_couple(mac)[0]

    def _resolve_MAC(self, mac: str) -> str:
        oui = ":".join(mac.split(":")[:3]).upper()
        if oui in self:
            return ":".join([self[oui][0]] + mac.split(":")[3:])
        return mac

    def lookup(self, mac: str) -> Tuple[str, str]:
        """The OUI's names, or the address twice where it is not listed."""
        return self._get_manuf_couple(mac)

    def reverse_lookup(self, name: str,
                       case_sensitive: bool = False) -> Dict[str, Tuple[str, str]]:
        """Every OUI registered to a name containing ``name``."""
        if case_sensitive:
            return {k: v for k, v in self.d.items() if any(name in z for z in v)}
        name = name.lower()
        return {k: v for k, v in self.d.items()
                if any(name in z.lower() for z in v)}

    def __dir__(self) -> List[str]:
        return ["_get_manuf", "_get_short_manuf", "_resolve_MAC", "lookup",
                "reverse_lookup"] + super().__dir__()


def load_manuf(filename: Optional[str] = None) -> ManufDA:
    """Wireshark's ``manuf`` file, or the copy bundled with wiry."""
    manufdb = ManufDA(_name=filename or "scapy/manufdb")

    def _process_data(fdesc: Any) -> None:
        for line in fdesc:
            try:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 2)
                oui, shrt = parts[:2]
                lng = parts[2].lstrip("#").strip() if len(parts) > 2 else ""
                manufdb[oui] = shrt, lng or shrt
            except Exception:
                log_loading.warning("Couldn't parse one line from [%s] [%r]",
                                    filename, line, exc_info=True)

    try:
        if not filename:
            raise IOError
        with open(filename, "r", errors="backslashreplace") as fdesc:
            _process_data(fdesc)
    except IOError:
        from .libs.manuf import DATA
        _process_data(iter(DATA.split("\n")))
    return manufdb


def load_bluetoothids(filename: Optional[str] = None) -> Dict[int, str]:
    from .libs.bluetoothids import DATA
    return DATA


def select_path(directories: List[str], filename: str) -> Optional[str]:
    """The first of ``directories`` holding ``filename``."""
    for directory in directories:
        path = os.path.join(directory, filename)
        if os.path.exists(path):
            return path
    return None


def _etc(name: str, windows_name: str) -> str:
    if _WINDOWS:
        return os.path.join(os.environ.get("SystemRoot", "C:\\Windows"),
                            "system32", "drivers", "etc", windows_name)
    return "/etc/" + name


def _load_services() -> Tuple[DADict, DADict, DADict]:
    tcp, udp, sctp = load_services(_etc("services", "services"))
    globals().update(TCP_SERVICES=tcp, UDP_SERVICES=udp, SCTP_SERVICES=sctp)
    return tcp, udp, sctp


_LOADERS: Dict[str, Callable[[], Any]] = {
    "IP_PROTOS": lambda: load_protocols(_etc("protocols", "protocol")),
    "TCP_SERVICES": lambda: _load_services()[0],
    "UDP_SERVICES": lambda: _load_services()[1],
    "SCTP_SERVICES": lambda: _load_services()[2],
    "ETHER_TYPES": lambda: load_ethertypes(
        None if _WINDOWS else "/etc/ethertypes"),
    "MANUFDB": lambda: load_manuf(None if _WINDOWS else select_path(
        ["/usr", "/usr/local", "/opt", "/opt/wireshark",
         "/Applications/Wireshark.app/Contents/Resources"],
        "share/wireshark/manuf")),
    "BLUETOOTH_CORE_COMPANY_IDENTIFIERS": load_bluetoothids,
}


def __getattr__(name: str) -> Any:
    loader = _LOADERS.get(name)
    if loader is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = globals()[name] = loader()
    return value


KBBaseType = Optional[Union[str, List[Tuple[str, Dict[str, Dict[str, str]]]]]]


class KnowledgeBase:
    """A database read from ``filename`` the first time it is asked for."""

    def __init__(self, filename: Optional[Any]):
        self.filename = filename
        self.base: KBBaseType = None

    def lazy_init(self) -> None:
        self.base = ""

    def reload(self, filename: Optional[Any] = None) -> None:
        if filename is not None:
            self.filename = filename
        oldbase = self.base
        self.base = None
        self.lazy_init()
        if self.base is None:
            self.base = oldbase

    def get_base(self) -> Any:
        if self.base is None:
            self.lazy_init()
        return self.base


__all__ = [
    "fixname", "DADict", "DADict_Exception",
    "ETHER_ANY", "ETHER_BROADCAST", "SOL_PACKET", "SO_ATTACH_FILTER",
    "SO_TIMESTAMPNS", "ETH_P_ALL", "ETH_P_IP", "ETH_P_ARP", "ETH_P_IPV6",
    "ETH_P_MACSEC",
    "ARPHDR_ETHER", "ARPHDR_METRICOM", "ARPHDR_PPP", "ARPHDR_LOOPBACK",
    "ARPHDR_TUN",
    *sorted(n for n in list(globals())
            if n.startswith(("DLT_", "ARPHRD_", "PPI_", "IPV6_ADDR_"))),
    "EPOCH", "MTU", "IANA_ENTERPRISE_NUMBERS", "scapy_data_cache",
    "load_protocols", "EtherDA", "load_ethertypes", "load_services",
    "ManufDA", "load_manuf", "load_bluetoothids", "select_path",
    "KBBaseType", "KnowledgeBase",
    *_LOADERS,
]
