# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/sessions.py (StringBuffer), scapy/layers/tls/crypto/md4.py,
#   scapy/utils.py (strrot),
#   scapy/config.py (crypto_validator), scapy/compat.py (bytes_base64)
#   scapy master, upstream commit e2e35c0
#   Copyright (C) Philippe Biondi and the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-04 — transcribed what NTLM and Kerberos lean on from scapy's
#     support modules; MD5 and HMAC-MD5 are hashlib's and hmac's.
"""Helpers the Python-modelled authentication layers share.

MD4 is here in Python because OpenSSL 3 drops it from `hashlib`, and NTLM's
password hash is MD4. Everything needing `cryptography` imports it on use, so
dissection never does.
"""

import base64
import hashlib
import hmac
import struct
from typing import Any, Callable, Optional, cast

from ._pyfields import bytes_encode, log_runtime

MTU = 1500


def strrot(s1: bytes, count: int, right: bool = True) -> bytes:
    """`s1` rotated by `count` octets."""
    off = count % len(s1)
    if right:
        return s1[-off:] + s1[:-off]
    return s1[off:] + s1[:off]


def bytes_base64(x: Any) -> bytes:
    return base64.encodebytes(bytes_encode(x)).replace(b"\n", b"")


def crypto_available() -> bool:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


def crypto_validator(func: Callable) -> Callable:
    """Refuse `func` with an ImportError naming the package where
    `cryptography` is not installed."""
    def func_in(*args: Any, **kwargs: Any) -> Any:
        if not crypto_available():
            raise ImportError(
                "Cannot execute crypto-related method! Please install "
                "python-cryptography v2.0 or later.")
        return func(*args, **kwargs)
    return func_in


class StringBuffer(object):
    """StringBuffer is an object used to re-order data received during
    a TCP transmission.

    Each TCP fragment contains a sequence number, which marks
    (relatively to the first sequence number) the index of the data contained
    in the fragment.

    If a TCP fragment is missed, this class will fill the missing space with
    zeros.

    :param max_gap: the largest missing range that will be zero-filled, in bytes.
        A sequence number far from the data already buffered would otherwise
        allocate the whole distance. Defaults to MTU.
    """

    def __init__(self, max_gap: int = MTU) -> None:
        self.content = bytearray(b"")
        self.content_len = 0
        self.noff = 0  # negative offset
        self.incomplete = []
        self.max_gap = max_gap

    def append(self, data: bytes, seq: Optional[int] = None) -> None:
        if not data:
            return
        data_len = len(data)
        if seq is None:
            seq = self.content_len
        seq = seq - 1 - self.noff
        if seq < 0:
            # Data is located before the start of the current buffer
            # (e.g. the first fragment was missing)
            if -seq - data_len > self.max_gap:
                log_runtime.warning(
                    "Dropped data further than allowed per 'max_gap'."
                )
                return
            self.content = bytearray(b"\x00" * (-seq)) + self.content
            self.content_len += (-seq)
            self.noff += seq
            seq = 0
        if seq + data_len > self.content_len:
            # Data is located after the end of the current buffer
            if seq - self.content_len > self.max_gap:
                log_runtime.warning(
                    "Dropped data further than allowed per 'max_gap'."
                )
                return
            self.content += b"\x00" * (seq - self.content_len + data_len)
            # As data was missing, mark it.
            # self.incomplete.append((self.content_len, seq))
            self.content_len = seq + data_len
            assert len(self.content) == self.content_len
        # XXX removes empty space marker.
        # for ifrag in self.incomplete:
        #     if [???]:
        #         self.incomplete.remove([???])
        memoryview(self.content)[seq:seq + data_len] = data

    def shiftleft(self, i: int) -> None:
        self.content = self.content[i:]
        self.content_len -= i

    def full(self):
        # Should only be true when all missing data was filled up,
        # (or there never was missing data)
        return bool(self)

    def clear(self):
        self.__init__()

    def __bool__(self):
        return bool(self.content_len)
    __nonzero__ = __bool__

    def __len__(self):
        return self.content_len

    def __bytes__(self):
        return bytes(self.content)

    def __str__(self):
        return cast(str, self.__bytes__())


class MD4:
    """
    An implementation of the MD4 hash algorithm.

    Modified to provide the same API as hashlib's.
    """
    name = 'md4'
    block_size = 64
    width = 32
    mask = 0xFFFFFFFF

    # Unlike, say, SHA-1, MD4 uses little-endian. Fascinating!
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def __init__(self, msg=b""):
        self.msg = msg

    def update(self, msg):
        self.msg += msg

    def digest(self):
        # Pre-processing: Total length is a multiple of 512 bits.
        ml = len(self.msg) * 8
        self.msg += b"\x80"
        self.msg += b"\x00" * (-(len(self.msg) + 8) % self.block_size)
        self.msg += struct.pack("<Q", ml)

        # Process the message in successive 512-bit chunks.
        self._process([self.msg[i: i + self.block_size]
                      for i in range(0, len(self.msg), self.block_size)])

        return struct.pack("<4L", *self.h)

    def _process(self, chunks):
        for chunk in chunks:
            X, h = list(struct.unpack("<16I", chunk)), self.h.copy()

            # Round 1.
            Xi = [3, 7, 11, 19]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n, Xi[n % 4]
                hn = h[i] + MD4.F(h[j], h[k], h[l]) + X[K]
                h[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 2.
            Xi = [3, 5, 9, 13]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n % 4 * 4 + n // 4, Xi[n % 4]
                hn = h[i] + MD4.G(h[j], h[k], h[l]) + X[K] + 0x5A827999
                h[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 3.
            Xi = [3, 9, 11, 15]
            Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = Ki[n], Xi[n % 4]
                hn = h[i] + MD4.H(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
                h[i] = MD4.lrot(hn & MD4.mask, S)

            self.h = [((v + n) & MD4.mask) for v, n in zip(self.h, h)]

    @staticmethod
    def F(x, y, z):
        return (x & y) | (~x & z)

    @staticmethod
    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def H(x, y, z):
        return x ^ y ^ z

    @staticmethod
    def lrot(value, n):
        lbits, rbits = (value << n) & MD4.mask, value >> (MD4.width - n)
        return lbits | rbits


class _Hash:
    def __init__(self, cls: Any):
        self._cls = cls

    def digest(self, data: bytes) -> bytes:
        return self._cls(data).digest()


def Hash_MD4() -> _Hash:
    return _Hash(MD4)


def Hash_MD5() -> _Hash:
    return _Hash(hashlib.md5)


def Hash_SHA() -> _Hash:
    return _Hash(hashlib.sha1)


def Hash_SHA256() -> _Hash:
    return _Hash(hashlib.sha256)


def Hash_SHA384() -> _Hash:
    return _Hash(hashlib.sha384)


def Hash_SHA512() -> _Hash:
    return _Hash(hashlib.sha512)


class Hmac_MD5:
    def __init__(self, key: bytes):
        self.key = key

    def digest(self, data: bytes) -> bytes:
        return hmac.new(self.key, data, hashlib.md5).digest()
