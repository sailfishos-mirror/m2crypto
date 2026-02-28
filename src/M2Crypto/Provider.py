"""
M2Crypto wrapper for OpenSSL PROVIDER API.
"""

import re
from typing import Optional

from M2Crypto import EVP, X509, m2


class ProviderError(ValueError):
    """Provider-related errors."""


m2.provider_init_error(ProviderError)  # type: ignore[attr-defined]


class Provider(object):
    """
    Wrapper for OpenSSL PROVIDER object.
    """

    def __init__(self, _id: str):
        """
        Initialize a provider with the given provider ID.

        :param _id: A string identifying the OpenSSL provider to load.
        :raises ProviderError: If the provider fails to load.
        """
        try:
            self._ptr = m2.provider_load(_id)
        except ProviderError:
            raise

        if self._ptr is None:
            raise ProviderError(f"Failed to load OpenSSL provider '{_id}'")

    def __del__(self) -> None:
        """
        Clean up the provider by unloading it from memory.

        Automatically called when the Provider object is garbage collected.
        Ensures that the underlying OpenSSL provider is properly unloaded
        to free system resources.
        """
        try:
            if getattr(self, "_ptr", None) is not None:
                m2.provider_unload(self._ptr)  # type: ignore[arg-type]
        except Exception:
            # Destructors must not raise.
            pass

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
        if "type=private" not in uri_split_list and "type=public" not in uri_split_list:
            raise ProviderError(
                "Key URI should indicate " + "'type=private' or 'type=public'"
            )

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

    def generate_rsa_key_pair(
        self, bits: int = 2048, exponent: int = 65537
    ) -> EVP.PKey:
        """
        Generate an RSA key pair using the provider.

        :param bits: Key length in bits (default: 2048).
        :param exponent: RSA public exponent (default: 65537).
        :return: An EVP.PKey object representing the generated RSA key pair.
        :raises ProviderError: If key generation fails.
        """
        if not isinstance(bits, int) or bits < 512:
            raise ProviderError(f"Invalid bits value: {bits}")
        if not isinstance(exponent, int) or exponent < 3:
            raise ProviderError(f"Invalid exponent value: {exponent}")

        cptr = m2.provider_generate_rsa_key_pair(bits, exponent, self._ptr)  # type: ignore[arg-type]
        if not cptr:
            raise ProviderError("Failed to generate RSA key pair")

        return EVP.PKey(cptr, _pyfree=1)

    def generate_ec_key_pair(self, curve_name: str = "prime256v1") -> EVP.PKey:
        """
        Generate an EC key pair using the provider.

        :param curve_name: Name of the elliptic curve (default: "prime256v1").
                           Common values include "prime256v1", "secp384r1", "secp521r1".
        :return: An EVP.PKey object representing the generated EC key pair.
        :raises ProviderError: If key generation fails.
        """
        if not isinstance(curve_name, str) or not curve_name:
            raise ProviderError(f"Invalid curve_name: {curve_name}")

        cptr = m2.provider_generate_ec_key_pair(curve_name, self._ptr)  # type: ignore[arg-type]
        if not cptr:
            raise ProviderError("Failed to generate EC key pair")

        return EVP.PKey(cptr, _pyfree=1)

    def destroy_key(self, uri: str, user_pin: Optional[str] = None) -> None:
        """
        Destroy a key stored in the provider.

        :param uri: A string URI specifying the key location to destroy.
        :param user_pin: Optional user PIN for authentication (default: None).
        :raises ProviderError: If the URI is not a string.
        :raises NotImplementedError: Key destruction is provider-specific and is not
                                     implemented by M2Crypto.
        """
        if not isinstance(uri, str):
            raise ProviderError(f"Wrong type {type(uri)} != str for uri")

        raise NotImplementedError(
            "Provider key destruction is provider-specific and is not implemented"
        )
