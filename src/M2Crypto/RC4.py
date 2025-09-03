"""M2Crypto wrapper for OpenSSL RC4 API.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

from typing import Optional
from M2Crypto import m2, types as C


class RC4(object):
    """Object interface to the stream cipher RC4."""

    def __init__(self, key: Optional[bytes] = None) -> None:
        self.cipher = m2.rc4_new()
        if key:
            m2.rc4_set_key(self.cipher, key)

    @staticmethod
    def rc4_free(cipher: C.RC4_KEY) -> None:
        m2.rc4_free(cipher)

    def __del__(self) -> None:
        if getattr(self, "cipher", None):
            self.rc4_free(self.cipher)

    def set_key(self, key: bytes) -> None:
        m2.rc4_set_key(self.cipher, key)

    def update(self, data: bytes) -> bytes:
        return m2.rc4_update(self.cipher, data)

    def final(self) -> str:
        return ""
