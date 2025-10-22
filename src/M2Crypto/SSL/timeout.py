"""Support for SSL socket timeouts.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved.

Copyright 2008 Heikki Toivonen. All rights reserved.
"""

__all__ = [
    "DEFAULT_TIMEOUT",
    "timeout",
    "struct_to_timeout",
    "struct_size",
]

import sys
import struct

from M2Crypto import m2

DEFAULT_TIMEOUT: int = 600


class timeout(object):
    sec: int
    microsec: int

    def __init__(self, sec: int = DEFAULT_TIMEOUT, microsec: int = 0) -> None:
        self.sec = sec
        self.microsec = microsec

    def pack(self) -> bytes:
        if sys.platform == "win32":
            millisec = int(self.sec * 1000 + round(float(self.microsec) / 1000))
            binstr = struct.pack("l", millisec)
        else:
            bits = m2.time_t_bits()
            if bits == 32:
                binstr = struct.pack("ii", self.sec, self.microsec)
            elif bits == 64:
                # handle both 64-bit and 32-bit+TIME_BITS=64
                binstr = struct.pack("qq", self.sec, self.microsec)
            else:
                raise ValueError(f"Unsupported time_t_bits: {bits}")
        return binstr


def struct_to_timeout(binstr: bytes) -> timeout:
    if sys.platform == "win32":
        millisec = struct.unpack("l", binstr)[0]
        # On py3, int/int performs exact division and returns float. We want
        # the whole number portion of the exact division result:
        sec = int(millisec / 1000)
        microsec = (millisec % 1000) * 1000
    else:
        bits = m2.time_t_bits()
        if bits == 32:
            (sec, microsec) = struct.unpack("ii", binstr)
        elif bits == 64:
            (sec, microsec) = struct.unpack("qq", binstr)
        else:
            raise ValueError(f"Unsupported time_t_bits: {bits}")
    return timeout(sec, microsec)


def struct_size() -> int:
    if sys.platform == "win32":
        return struct.calcsize("l")
    else:
        bits = m2.time_t_bits()
        if bits == 32:
            return struct.calcsize("ii")
        elif bits == 64:
            return struct.calcsize("qq")
        else:
            raise ValueError(f"Unsupported time_t_bits: {bits}")
