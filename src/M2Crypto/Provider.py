"""
M2Crypto wrapper for OpenSSL PROVIDER API.
"""

import re

from M2Crypto import EVP, X509, m2


class ProviderError(ValueError):
    """Provider-related errors."""


m2.provider_init_error(ProviderError)


class Provider(object):
    """
    Wrapper for OpenSSL PROVIDER object.
    """

    def __init__(self, _id: str):
        """
        Initialize a provider with the given provider ID.

        :param _id: A string identifying the OpenSSL provider to load.
        :raises RuntimeError: If the provider fails to load.
        """
        self._ptr = m2.provider_load(_id)
        if not self._ptr:
            raise RuntimeError(f"Failed to load OpenSSL provider '{_id}'")

    def __del__(self) -> None:
        """
        Clean up the provider by unloading it from memory.

        Automatically called when the Provider object is garbage collected.
        Ensures that the underlying OpenSSL provider is properly unloaded
        to free system resources.
        """
        if self._ptr:
            m2.provider_unload(self._ptr)

    def load_key(self, uri: str) -> EVP.PKey:
        """
        Load a private or public key from a provider using the given URI.

        :param uri: A string URI specifying the key location and type.
                    The URI should include 'type=private' or 'type=public'
                    to indicate the key type.
        :return: An EVP.PKey object representing the loaded key.
        :raises ProviderError: If the URI is not a string, doesn't specify key type,
                              or if the key or card is not found.
        """
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
        """
        Load a certificate from a provider using the given URI.

        :param uri: A string URI specifying the certificate location.
        :return: An X509.X509 object representing the loaded certificate.
        :raises ProviderError: If the URI is not a string or if the
                               certificate or card is not found.
        """
        if not isinstance(uri, str):
            raise ProviderError(f"Wrong type {type(uri)} != str for uri")

        cptr = m2.provider_load_certificate(uri)
        if not cptr:
            raise ProviderError("Certificate or card not found")

        return X509.X509(cptr, _pyfree=1)
