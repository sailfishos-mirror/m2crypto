# vim: sts=4 sw=4 et
from __future__ import absolute_import

"""
M2Crypto wrapper for OpenSSL ENGINE API.

Pavel Shramov
IMEC MSU
"""

from M2Crypto import EVP, Err, X509, m2
from typing import Callable, Optional, Union  # noqa


class EngineError(Exception):
    pass


m2.engine_init_error(EngineError)


class Engine(object):
    """Wrapper for ENGINE object."""

    m2_engine_free = m2.engine_free

    def __init__(
        self,
        id: Optional[bytes] = None,
        _ptr: Optional[bytes] = None,
        _pyfree: int = 1,
    ) -> None:
        """Create new Engine from ENGINE pointer or obtain by id"""
        if not _ptr and not id:
            raise ValueError("No engine id specified")
        self._ptr = _ptr
        if not self._ptr:
            self._ptr = m2.engine_by_id(id)
            if not self._ptr:
                raise ValueError("Unknown engine: %s" % id)
        self._pyfree = _pyfree

    def __del__(self) -> None:
        if getattr(self, '_pyfree', 0):
            self.m2_engine_free(self._ptr)

    def init(self) -> int:
        """Obtain a functional reference to the engine.

        :return: 0 on error, non-zero on success."""
        return m2.engine_init(self._ptr)

    def finish(self) -> int:
        """Release a functional and structural reference to the engine."""
        return m2.engine_finish(self._ptr)

    def ctrl_cmd_string(
        self,
        cmd: Union[str, bytes],
        arg: Union[str, bytes, None],
        optional: int = 0,
    ) -> None:
        """Call ENGINE_ctrl_cmd_string"""
        if isinstance(cmd, bytes):
            cmd = cmd.decode()
        if arg is not None and isinstance(arg, bytes):
            arg = arg.decode()
        if not m2.engine_ctrl_cmd_string(
            self._ptr, cmd, arg, optional
        ):
            raise EngineError(Err.get_error())

    def get_name(self) -> bytes:
        """Return engine name"""
        return m2.engine_get_name(self._ptr)

    def get_id(self) -> bytes:
        """Return engine id"""
        return m2.engine_get_id(self._ptr)

    def set_default(self, methods: int = m2.ENGINE_METHOD_ALL) -> int:
        """
        Use this engine as default for methods specified in argument

        :param methods: Possible values are bitwise OR of m2.ENGINE_METHOD_*
        """
        return m2.engine_set_default(self._ptr, methods)

    def _engine_load_key(
        self, func: Callable, name: bytes, pin: Optional[bytes] = None
    ) -> EVP.PKey:
        """Helper function for loading keys"""
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
        self, name: bytes, pin: Optional[bytes] = None
    ) -> X509.X509:
        """Load private key with engine methods (e.g from smartcard).
        If pin is not set it will be asked
        """
        return self._engine_load_key(
            m2.engine_load_private_key, name, pin
        )

    def load_public_key(
        self, name: bytes, pin: Optional[bytes] = None
    ) -> EVP.PKey:
        """Load public key with engine methods (e.g from smartcard)."""
        return self._engine_load_key(
            m2.engine_load_public_key, name, pin
        )

    def load_certificate(self, name: bytes) -> X509.X509:
        """Load certificate from engine (e.g from smartcard).
        NOTE: This function may be not implemented by engine!"""
        cptr = m2.engine_load_certificate(self._ptr, name)
        if not cptr:
            raise EngineError("Certificate or card not found")
        return X509.X509(cptr, _pyfree=1)


def load_dynamic_engine(
    id: bytes, sopath: Union[str, bytes]
) -> Engine:
    """Load and return dymanic engine from sopath and assign id to it"""
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
    """Load dynamic engine"""
    m2.engine_load_dynamic()


def load_openssl() -> None:
    """Load openssl engine"""
    m2.engine_load_openssl()


def cleanup() -> None:
    """If you load any engines, you need to clean up after your application
    is finished with the engines."""
    m2.engine_cleanup()
