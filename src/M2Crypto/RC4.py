"""M2Crypto wrapper for OpenSSL RC4 API.

WARNING: RC4 is cryptographically broken (RFC 7465 prohibits its use
in TLS).  This module is kept only for interoperability with legacy
data formats and will be removed in a future release.  New code
should use AES (e.g. EVP.Cipher with aes_256_gcm) instead.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved.
"""

import warnings

from typing import Optional
from M2Crypto import m2, types as C


class RC4(object):
    """Object interface to the stream cipher RC4.

    .. deprecated:: 0.49
       RC4 is insecure (RFC 7465); use AES instead.  Instantiating
       this class emits a :class:`DeprecationWarning`.
    """

    def __init__(self, key: Optional[bytes] = None) -> None:
        warnings.warn(
            "M2Crypto.RC4 is deprecated and will be removed in a future "
            "release; RC4 is insecure (RFC 7465). Use AES instead.",
            DeprecationWarning,
            stacklevel=2,
        )
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
