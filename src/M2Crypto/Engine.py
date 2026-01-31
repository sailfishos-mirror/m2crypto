"""
M2Crypto wrapper for OpenSSL ENGINE API.

Copyright (c) Pavel Shramov, IMEC MSU.
"""

from M2Crypto import EVP, Err, X509, m2, types as C
from typing import Callable, Optional, Union  # noqa


class EngineError(Exception):
    """Engine-related errors."""


m2.engine_init_error(EngineError)


class Engine(object):
    """
    Wrapper for ENGINE object.
    """

    def __init__(
        self,
        id: Union[str, bytes, None] = None,
        _ptr: Optional[C.ENGINE] = None,
        _pyfree: int = 1,
    ) -> None:
        """
        Create new Engine from ENGINE pointer or obtain by id.

        :param id: Engine identifier string (e.g., 'dynamic', 'openssl').
        :param _ptr: Optional ENGINE pointer for internal use.
        :param _pyfree: Internal flag indicating whether to free the ENGINE pointer.
        :raises ValueError: If id is None or if the specified engine is not found.
        """
        self._ptr: C.ENGINE
        if _ptr is None:
            if id is None:
                raise ValueError("Trying to search engine by id of None.")
            if isinstance(id, bytes):
                id = id.decode()
            _ptr = m2.engine_by_id(id)
            if _ptr is None:
                raise ValueError("Unknown engine: %s" % id)
        self._ptr = _ptr
        self._pyfree = _pyfree

    @staticmethod
    def m2_engine_free(obj: C.ENGINE) -> None:
        """
        Free an ENGINE object.

        :param obj: ENGINE pointer to free.
        """
        m2.engine_free(obj)

    def __del__(self) -> None:
        """
        Destructor that frees the ENGINE object if needed.

        Automatically called when the Engine object is garbage collected.
        Frees the underlying ENGINE pointer if the object is responsible
        for managing its lifecycle.
        """
        if getattr(self, '_pyfree', 0) and self._ptr:
            m2.engine_free(self._ptr)

    def init(self) -> int:
        """
        Obtain a functional reference to the engine.

        :return: 0 on error, non-zero on success.
        """
        return m2.engine_init(self._ptr)

    def finish(self) -> int:
        """
        Release a functional and structural reference to the engine.

        :return: 0 on error, non-zero on success.
        """
        return m2.engine_finish(self._ptr)

    def ctrl_cmd_string(
        self,
        cmd: Union[str, bytes],
        arg: Union[str, bytes, None],
        optional: int = 0,
    ) -> None:
        """
        Send a control command to the engine.

        :param cmd: Command string to send to the engine.
        :param arg: Optional argument for the command.
        :param optional: Flag indicating whether the command is optional (0 or 1).
        :raises EngineError: If the command fails.
        """
        if isinstance(cmd, bytes):
            cmd = cmd.decode()
        if arg is not None and isinstance(arg, bytes):
            arg = arg.decode()
        if not m2.engine_ctrl_cmd_string(
            self._ptr, cmd, arg, optional
        ):
            raise EngineError(Err.get_error())

    def get_name(self) -> str:
        """
        Get the engine's human-readable name.

        :return: The engine's name as a string.
        """
        return m2.engine_get_name(self._ptr)

    def get_id(self) -> str:
        """
        Get the engine's identifier.

        :return: The engine's identifier string.
        """
        return m2.engine_get_id(self._ptr)

    def set_default(self, methods: int = m2.ENGINE_METHOD_ALL) -> int:
        """
        Set this engine as the default for specified cryptographic methods.

        :param methods: Bitwise OR of method flags (e.g., m2.ENGINE_METHOD_RSA,
                       m2.ENGINE_METHOD_DSA, m2.ENGINE_METHOD_ALL).
        :return: 0 on error, non-zero on success.
        """
        return m2.engine_set_default(self._ptr, methods)

    def _engine_load_key(
        self, func: Callable, name: Union[str, bytes], pin: Union[str, bytes, None] = None
    ) -> EVP.PKey:
        """
        Internal helper function for loading keys from engine.

        :param func: The engine function to call for loading the key.
        :param name: Key identifier or name.
        :param pin: Optional PIN for accessing the key.
        :return: EVP.PKey object containing the loaded key.
        :raises EngineError: If key loading fails.
        """
        if isinstance(name, bytes):
            name = name.decode()
        if pin is not None and isinstance(pin, bytes):
            pin = pin.decode()
        ui = m2.ui_openssl()
        cbd = m2.engine_pkcs11_data_new(pin)
        try:
            kptr = func(self._ptr, name, ui, cbd)
            if not kptr:
                raise EngineError(Err.get_error())
            key = EVP.PKey(kptr, _pyfree=1)
        finally:
        m2.engine_pkcs11_data_free(cbd)
        return key

    def load_private_key(
        self, name: Union[str, bytes], pin: Union[str, bytes, None] = None
    ) -> EVP.PKey:
        """
        Load a private key using engine methods.

        :param name: Key identifier or name.
        :param pin: Optional PIN for accessing the key. If not provided, the user
                    will be prompted for it.
        :return: EVP.PKey object containing the loaded private key.
        :raises EngineError: If the private key cannot be loaded.
        """
        return self._engine_load_key(
            m2.engine_load_private_key, name, pin
        )

    def load_public_key(
        self, name: Union[str, bytes], pin: Union[str, bytes, None] = None
    ) -> EVP.PKey:
        """
        Load a public key using engine methods.

        :param name: Key identifier or name.
        :param pin: Optional PIN for accessing the key.
        :return: EVP.PKey object containing the loaded public key.
        :raises EngineError: If the public key cannot be loaded.
        """
        return self._engine_load_key(
            m2.engine_load_public_key, name, pin
        )

    def load_certificate(self, name: Union[str, bytes]) -> X509.X509:
        """
        Load a certificate using engine methods.

        :param name: Certificate identifier or name.
        :return: X509.X509 object containing the loaded certificate.
        :raises EngineError: If the certificate cannot be loaded or the card is not found.
        """
        if isinstance(name, bytes):
            name = name.decode()
        cptr = m2.engine_load_certificate(self._ptr, name)
        if not cptr:
            raise EngineError("Certificate or card not found")
        return X509.X509(cptr, _pyfree=1)


def load_dynamic_engine(
    id: bytes, sopath: Union[str, bytes]
) -> Engine:
    """
    Load and return a dynamic engine from a shared object path.

    :param id: Engine identifier as bytes.
    :param sopath: Path to the shared object file containing the engine.
    :return: Engine object representing the loaded dynamic engine.
    """
    if isinstance(sopath, str):
        sopath = sopath.encode('utf8')
    m2.engine_load_dynamic()
    e = Engine('dynamic')
    e.ctrl_cmd_string('SO_PATH', sopath)
    e.ctrl_cmd_string('ID', id)
    e.ctrl_cmd_string('LIST_ADD', '1')
    e.ctrl_cmd_string('LOAD', None)
    return e


def load_dynamic() -> None:
    """
    Load the dynamic engine.

    This function loads the OpenSSL dynamic engine, which allows loading
    external engines from shared libraries at runtime.
    """
    m2.engine_load_dynamic()


def load_openssl() -> None:
    """
    Load the OpenSSL software engine.

    This function loads the built-in OpenSSL software engine, which
    provides cryptographic operations using OpenSSL's software
    implementations.
    """
    m2.engine_load_openssl()


def cleanup() -> None:
    """
    Clean up all loaded engines.

    This function should be called when your application is finished
    with all engines to properly release resources and clean up.
    """
    m2.engine_cleanup()
