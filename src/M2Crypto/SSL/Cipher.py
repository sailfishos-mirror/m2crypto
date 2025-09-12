"""SSL Ciphers

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

__all__ = ["Cipher", "Cipher_Stack"]

from M2Crypto import m2, types as C
from typing import Iterable  # noqa


class Cipher(object):
    cipher: C.SSL_CIPHER

    def __init__(self, cipher: C.SSL_CIPHER, _pyfree: int = 0) -> None:
        self.cipher = cipher

    def __len__(self) -> int:
        return m2.ssl_cipher_get_bits(self.cipher)

    def __repr__(self) -> str:
        return "%s-%s" % (self.name(), len(self))

    def __str__(self) -> str:
        return "%s-%s" % (self.name(), len(self))

    def version(self) -> str:
        return m2.ssl_cipher_get_version(self.cipher)

    def name(self) -> str:
        return m2.ssl_cipher_get_name(self.cipher)


class Cipher_Stack(object):
    stack: C.STACK_OF_SSL_CIPHER

    def __init__(self, stack: C.STACK_OF_SSL_CIPHER, _pyfree: int = 0) -> None:
        """
        :param stack: binary of the C-type STACK_OF(SSL_CIPHER)
        """
        self.stack = stack

    def __len__(self) -> int:
        return m2.sk_ssl_cipher_num(self.stack)

    def __getitem__(self, idx: int) -> Cipher:
        if not 0 <= idx < m2.sk_ssl_cipher_num(self.stack):
            raise IndexError("index out of range")
        v = m2.sk_ssl_cipher_value(self.stack, idx)
        return Cipher(v)

    def __iter__(self) -> Iterable:
        for i in range(m2.sk_ssl_cipher_num(self.stack)):
            yield self[i]
