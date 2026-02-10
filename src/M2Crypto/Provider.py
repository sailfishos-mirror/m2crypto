"""
M2Crypto wrapper for OpenSSL PROVIDER API.
"""

import re

from M2Crypto import EVP, X509, m2


class ProviderError(ValueError):
    pass


m2.provider_init_error(ProviderError)


class Provider(object):
    """Wrapper for PROVIDER object."""

    def __init__(self, _id: str):
        self._ptr = m2.provider_load(_id)
        if not self._ptr:
            raise RuntimeError(f"Failed to load OpenSSL provider '{_id}'")

    def __del__(self) -> None:
        if self._ptr:
            m2.provider_unload(self._ptr)

    def load_key(self, uri: str) -> EVP.PKey:
        """Load a private or public key with provider methods (e.g from smartcard)."""
        if not isinstance(uri, str):
            raise ProviderError(f"Wrong type {type(uri)} != str for uri")

        uri_split_list = re.split(";|\\?", uri)
        if "type=private" not in uri_split_list and \
               "type=public" not in uri_split_list:
            raise ProviderError("Key URI should indicate " +
                                "'type=private' or 'type=public'")

        cptr = m2.provider_load_key(uri)
        if not cptr:
            raise ProviderError("Key or card not found")

        return EVP.PKey(cptr, _pyfree=1)

    def load_certificate(self, uri: str) -> X509.X509:
        """Load certificate from provider (e.g from smartcard)."""
        if not isinstance(uri, str):
            raise ProviderError(f"Wrong type {type(uri)} != str for uri")

        cptr = m2.provider_load_certificate(uri)
        if not cptr:
            raise ProviderError("Certificate or card not found")

        return X509.X509(cptr, _pyfree=1)
