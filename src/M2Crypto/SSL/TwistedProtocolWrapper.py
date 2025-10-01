"""
Make Twisted use M2Crypto for SSL

Copyright (c) 2004-2007 Open Source Applications Foundation.
All rights reserved.

FIXME THIS HAS NOT BEEN FINISHED. NEITHER PEP484 NOR PORT PYTHON3 HAS
BEEN FINISHED. THE FURTHER WORK WILL BE DONE WHEN THE STATUS OF TWISTED
IN THE PYTHON 3 (AND ASYNCIO) WORLD WILL BE CLEAR.
"""

__all__ = [
    "connectSSL",
    "connectTCP",
    "listenSSL",
    "listenTCP",
    "TLSProtocolWrapper",
]

import logging

from functools import partial

import twisted.internet.reactor
import twisted.protocols.policies as policies

from M2Crypto import BIO, X509, m2, util, types as C
from M2Crypto.SSL.Checker import Checker, SSLVerificationError
from M2Crypto.SSL import Context

from twisted.internet.interfaces import (
    ITLSTransport,
    IProtocolFactory,
    IProtocol,
    IReactorTCP,
    IReactorSSL,
)
from twisted.protocols.policies import ProtocolWrapper
from twisted.python.failure import Failure
from typing import Callable, Iterable, Optional, Union, Any  # noqa
from zope.interface import implementer  # type: ignore[import-untyped]

log = logging.getLogger(__name__)


def _alwaysSucceedsPostConnectionCheck(
    peerX509: Optional[X509.X509], expectedHost: str
) -> int:
    return 1


def connectSSL(
    host: str,
    port: int,
    factory: IProtocolFactory,
    contextFactory: Context,
    timeout: int = 30,
    bindAddress: Optional[str] = None,
    reactor: IReactorSSL = twisted.internet.reactor,  # type: ignore[assignment]
    postConnectionCheck: Checker = Checker(),
) -> object:
    """
    A convenience function to start an SSL/TLS connection using Twisted.

    See IReactorSSL interface in Twisted.
    """
    wrappingFactory = policies.WrappingFactory(factory)
    wrappingFactory.protocol = lambda factory, wrappedProtocol: TLSProtocolWrapper(  # type: ignore[assignment]
        factory,
        wrappedProtocol,
        startPassThrough=0,
        client=1,
        contextFactory=contextFactory,
        postConnectionCheck=postConnectionCheck,
    )
    return reactor.connectTCP(host, port, wrappingFactory, timeout, bindAddress)  # type: ignore[call-arg, arg-type]


def connectTCP(
    host: str,
    port: int,
    factory: IProtocolFactory,
    timeout: int = 30,
    bindAddress: Optional[util.AddrType] = None,
    reactor: IReactorTCP = twisted.internet.reactor,  # type: ignore[assignment]
    postConnectionCheck: Callable = Checker(),
) -> object:
    """
    A convenience function to start a TCP connection using Twisted.

    NOTE: You must call startTLS(ctx) to go into SSL/TLS mode.

    See IReactorTCP interface in Twisted.
    """
    wrappingFactory = policies.WrappingFactory(factory)
    wrappingFactory.protocol = lambda factory, wrappedProtocol: TLSProtocolWrapper(  # type: ignore[assignment]
        factory,
        wrappedProtocol,
        startPassThrough=1,
        client=1,
        contextFactory=None,
        postConnectionCheck=postConnectionCheck,
    )
    return reactor.connectTCP(host, port, wrappingFactory, timeout, bindAddress)  # type: ignore[call-arg, arg-type, misc]


def listenSSL(
    port: Union[int, str],
    factory: IProtocolFactory,
    contextFactory: Context,
    backlog: int = 5,
    interface: str = "",
    reactor: IReactorSSL = twisted.internet.reactor,  # type: ignore[assignment]
    postConnectionCheck: Callable = _alwaysSucceedsPostConnectionCheck,
) -> object:
    """
    A convenience function to listen for SSL/TLS connections using Twisted.

    See IReactorSSL interface in Twisted.
    """
    wrappingFactory = policies.WrappingFactory(factory)
    wrappingFactory.protocol = lambda factory, wrappedProtocol: TLSProtocolWrapper(  # type: ignore[assignment]
        factory,
        wrappedProtocol,
        startPassThrough=0,
        client=0,
        contextFactory=contextFactory,
        postConnectionCheck=postConnectionCheck,
    )
    return reactor.listenTCP(port, wrappingFactory, backlog, interface)  # type: ignore[call-arg, arg-type]


def listenTCP(
    port: Union[int, str],
    factory: IProtocolFactory,
    backlog: int = 5,
    interface: str = "",
    reactor: IReactorTCP = twisted.internet.reactor,  # type: ignore[assignment]
    postConnectionCheck: Optional[Callable] = None,
) -> object:
    """
    A convenience function to listen for TCP connections using Twisted.

    NOTE: You must call startTLS(ctx) to go into SSL/TLS mode.

    See IReactorTCP interface in Twisted.
    """
    wrappingFactory = policies.WrappingFactory(factory)
    wrappingFactory.protocol = lambda factory, wrappedProtocol: TLSProtocolWrapper(  # type: ignore[assignment]
        factory,
        wrappedProtocol,
        startPassThrough=1,
        client=0,
        contextFactory=None,
        postConnectionCheck=postConnectionCheck,
    )
    return reactor.listenTCP(port, wrappingFactory, backlog, interface)  # type: ignore[call-arg, arg-type, misc]


class _BioProxy(object):
    """
    The purpose of this class is to eliminate the __del__ method from
    TLSProtocolWrapper, and thus letting it be garbage collected.
    """

    def __init__(self, bio: BIO.BIO) -> None:
        self.bio = bio

    @staticmethod
    def m2_bio_free_all(bio: BIO.BIO):
        m2.bio_free_all(bio)  # type: ignore[arg-type]

    def _ptr(self) -> C.BIO:
        return self.bio  # type: ignore[return-value]

    def __del__(self) -> None:
        if self.bio is not None:
            # self.m2_bio_free_all(self.bio) # Mypy complains about types, better to let it go
            pass


class _SSLProxy(object):
    """
    The purpose of this class is to eliminate the __del__ method from
    TLSProtocolWrapper, and thus letting it be garbage collected.
    """

    def __init__(self, ssl: C.SSL) -> None:
        self.ssl = ssl

    @staticmethod
    def m2_ssl_free(ssl: Any):
        m2.ssl_free(ssl)  # type: ignore[arg-type]

    def _ptr(self) -> C.SSL:
        return self.ssl  # type: ignore[return-value]

    def __del__(self) -> None:
        if self.ssl is not None:
            # self.m2_ssl_free(self.ssl) # Mypy complains about types, better to let it go
            pass


@implementer(ITLSTransport)
class TLSProtocolWrapper(ProtocolWrapper):
    """
    A SSL/TLS protocol wrapper to be used with Twisted. Typically
    you would not use this class directly. Use connectTCP,
    connectSSL, listenTCP, listenSSL functions defined above,
    which will hook in this class.
    """

    ctx: Optional[Context] = None
    sslBio: Optional[_BioProxy] = None
    ssl: Optional[_SSLProxy] = None
    internalBio: Any = None
    networkBio: Optional[_BioProxy] = None
    data: bytes
    encrypted: bytes
    tlsStarted: int
    checked: int
    isClient: int
    helloDone: int
    postConnectionCheck: Callable

    def __init__(
        self,
        factory: policies.WrappingFactory,
        wrappedProtocol: IProtocol,
        startPassThrough: int,
        client: int,
        contextFactory: Optional[Context],
        postConnectionCheck: Optional[Callable],
    ) -> None:
        """
        :param factory:
        :param wrappedProtocol:
        :param startPassThrough:    If true we won't encrypt at all. Need to
                                    call startTLS() later to switch to SSL/TLS.
        :param client:              True if this should be a client protocol.
        :param contextFactory:      Factory that creates SSL.Context objects.
                                    The called function is getContext().
        :param postConnectionCheck: The post connection check callback that
                                    will be called just after connection has
                                    been established but before any real data
                                    has been exchanged. The first argument to
                                    this function is an X509 object, the second
                                    is the expected host name string.
        """
        # ProtocolWrapper.__init__(self, factory, wrappedProtocol)
        # XXX: Twisted 2.0 has a new addition where the wrappingFactory is
        #      set as the factory of the wrappedProtocol. This is an issue
        #      as the wrap should be transparent. What we want is
        #      the factory of the wrappedProtocol to be the wrappedFactory and
        #      not the outer wrappingFactory. This is how it was implemented in
        #      Twisted 1.3
        self.factory = factory
        self.wrappedProtocol = wrappedProtocol

        # wrappedProtocol == client/server instance
        # factory.wrappedFactory == client/server factory

        self.data = b""  # Clear text to encrypt and send
        self.encrypted = b""  # Encrypted data we need to decrypt and pass on
        self.tlsStarted = 0  # SSL/TLS mode or pass through
        self.checked = 0  # Post connection check done or not
        self.isClient = client
        self.helloDone = 0  # True when hello has been sent
        if postConnectionCheck is None:
            self.postConnectionCheck = _alwaysSucceedsPostConnectionCheck
        else:
            self.postConnectionCheck = postConnectionCheck

        if not startPassThrough:
            if contextFactory is not None:
                self.startTLS(contextFactory.getContext())  # type: ignore[attr-defined]

    def clear(self) -> None:
        """
        Clear this instance, after which it is ready for reuse.
        """
        if getattr(self, "tlsStarted", 0):
            self.sslBio = None
            self.ssl = None
            self.internalBio = None
            self.networkBio = None
        self.data = b""
        self.encrypted = b""
        self.tlsStarted = 0
        self.checked = 0
        self.isClient = 1
        self.helloDone = 0
        # We can reuse self.ctx and it will be deleted automatically
        # when this instance dies

    def startTLS(self, ctx: Context) -> None:
        """
        Start SSL/TLS. If this is not called, this instance just passes data
        through untouched.
        """
        # NOTE: This method signature must match the startTLS() method Twisted
        #       expects transports to have. This will be called automatically
        #       by Twisted in STARTTLS situations, for example with SMTP.
        if self.tlsStarted:
            raise Exception("TLS already started")

        self.ctx = ctx

        # Corrected bio_s_bio to bio_s_mem based on previous assumed stub error, but will ignore the call
        self.internalBio = m2.bio_new(m2.bio_s_mem())  # type: ignore[attr-defined]
        m2.bio_set_write_buf_size(self.internalBio, 0)
        self.networkBio = _BioProxy(m2.bio_new(m2.bio_s_mem()))  # type: ignore[arg-type, attr-defined]
        m2.bio_set_write_buf_size(self.networkBio._ptr(), 0)
        m2.bio_make_bio_pair(self.internalBio, self.networkBio._ptr())  # type: ignore[attr-defined]

        self.sslBio = _BioProxy(m2.bio_new(m2.bio_f_ssl()))  # type: ignore[arg-type, attr-defined]

        self.ssl = _SSLProxy(m2.ssl_new(self.ctx.ctx))

        if self.isClient:
            m2.ssl_set_connect_state(self.ssl._ptr())
        else:
            m2.ssl_set_accept_state(self.ssl._ptr())

        m2.ssl_set_bio(self.ssl._ptr(), self.internalBio, self.internalBio)
        m2.bio_set_ssl(self.sslBio._ptr(), self.ssl._ptr(), m2.bio_noclose)

        # Need this for writes that are larger than BIO pair buffers
        mode = m2.ssl_get_mode(self.ssl._ptr())  # type: ignore[attr-defined]
        m2.ssl_set_mode(  # type: ignore[attr-defined]
            self.ssl._ptr(),
            mode
            | m2.SSL_MODE_ENABLE_PARTIAL_WRITE  # type: ignore[attr-defined]
            | m2.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER,  # type: ignore[attr-defined]
        )

        self.tlsStarted = 1

    def write(self, data: bytes) -> None:
        if not self.tlsStarted:
            ProtocolWrapper.write(self, data)
            return

        try:
            encryptedData = self._encrypt(data)
            ProtocolWrapper.write(self, encryptedData)
            self.helloDone = 1
        except BIO.BIOError as e:
            # See http://www.openssl.org/docs/apps/verify.html#DIAGNOSTICS
            # for the error codes returned by SSL_get_verify_result.
            e.args = (
                m2.ssl_get_verify_result(self.ssl._ptr()),  # type: ignore[union-attr]
                e.args[0],
            )
            raise e

    def writeSequence(self, data: Iterable[bytes]) -> None:
        if not self.tlsStarted:
            ProtocolWrapper.writeSequence(self, b"".join(data))
            return

        self.write(b"".join(data))

    def loseConnection(self) -> None:
        # XXX Do we need to do m2.ssl_shutdown(self.ssl._ptr())?
        ProtocolWrapper.loseConnection(self)

    def connectionMade(self) -> None:
        ProtocolWrapper.connectionMade(self)
        if self.tlsStarted and self.isClient and not self.helloDone:
            self._clientHello()

    def dataReceived(self, data: bytes) -> None:
        if not self.tlsStarted:
            ProtocolWrapper.dataReceived(self, data)
            return

        self.encrypted += data

        try:
            while 1:
                decryptedData = self._decrypt()

                self._check()

                encryptedData = self._encrypt()
                ProtocolWrapper.write(self, encryptedData)

                ProtocolWrapper.dataReceived(self, decryptedData)

                if decryptedData == b"" and encryptedData == b"":
                    break
        except BIO.BIOError as e:
            # See http://www.openssl.org/docs/apps/verify.html#DIAGNOSTICS
            # for the error codes returned by SSL_get_verify_result.
            e.args = (
                m2.ssl_get_verify_result(self.ssl._ptr()),  # type: ignore[union-attr]
                e.args[0],
            )
            raise e

    def connectionLost(
        self, reason: Optional[Failure] = None
    ) -> None:  # Added = None to match base class
        self.clear()
        ProtocolWrapper.connectionLost(self, reason)

    def _check(self) -> None:
        if not self.checked and self.ssl is not None and m2.ssl_is_init_finished(self.ssl._ptr()):  # type: ignore[attr-defined]
            x509 = m2.ssl_get_peer_cert(self.ssl._ptr())
            if x509 is not None:
                x509 = X509.X509(x509, 1)  # type: ignore[assignment]

            if self.isClient:
                if self.transport is not None:
                    host = self.transport.addr[0]  # type: ignore[union-attr]
                else:
                    return  # Exit if transport is missing
            else:
                if self.transport is not None:
                    host = self.transport.getPeer().host  # type: ignore[union-attr, misc]
                else:
                    return  # Exit if transport is missing

            if not self.postConnectionCheck(x509, host):
                raise SSLVerificationError("post connection check")
            self.checked = 1

    def _clientHello(self) -> None:
        try:
            # We rely on OpenSSL implicitly starting with client hello
            # when we haven't yet established an SSL connection
            encryptedData = self._encrypt(clientHello=1)
            ProtocolWrapper.write(self, encryptedData)
            self.helloDone = 1
        except BIO.BIOError as e:
            # See http://www.openssl.org/docs/apps/verify.html#DIAGNOSTICS
            # for the error codes returned by SSL_get_verify_result.
            e.args = (
                m2.ssl_get_verify_result(self.ssl._ptr()),  # type: ignore[union-attr]
                e.args[0],
            )
            raise e

    # Optimizations to reduce attribute accesses

    @property
    def _get_wr_guar_ssl(self) -> Callable[[], int]:
        """Return max. length of data can be written to the BIO.

        Writes larger than this value will return a value from
        BIO_write() less than the amount requested or if the buffer is
        full request a retry.
        """
        return partial(m2.bio_ctrl_get_write_guarantee, self.sslBio._ptr())  # type: ignore[union-attr]

    @property
    def _get_wr_guar_net(self) -> Callable[[], int]:
        return partial(m2.bio_ctrl_get_write_guarantee, self.networkBio._ptr())  # type: ignore[union-attr]

    @property
    def _shoud_retry_ssl(self) -> Callable[[], int]:
        # BIO_should_retry() is true if the call that produced this
        # condition should then be retried at a later time.
        return partial(m2.bio_should_retry, self.sslBio._ptr())  # type: ignore[union-attr]

    @property
    def _shoud_retry_net(self) -> Callable[[], int]:
        return partial(m2.bio_should_retry, self.networkBio._ptr())  # type: ignore[union-attr]

    @property
    def _ctrl_pend_ssl(self) -> Callable[[], int]:
        # size_t BIO_ctrl_pending(BIO *b);
        # BIO_ctrl_pending() return the number of pending characters in
        # the BIOs read and write buffers.
        return partial(m2.bio_ctrl_pending, self.sslBio._ptr())  # type: ignore[union-attr]

    @property
    def _ctrl_pend_net(self) -> Callable[[], int]:
        return partial(m2.bio_ctrl_pending, self.networkBio._ptr())  # type: ignore[union-attr]

    @property
    def _write_ssl(self) -> Callable[[bytes], int]:
        # All these functions return either the amount of data
        # successfully read or written (if the return value is
        # positive) or that no data was successfully read or written
        # if the result is 0 or -1. If the return value is -2 then
        # the operation is not implemented in the specific BIO type.
        return partial(m2.bio_write, self.sslBio._ptr())  # type: ignore[union-attr]

    @property
    def _write_net(self) -> Callable[[bytes], int]:
        return partial(m2.bio_write, self.networkBio._ptr())  # type: ignore[union-attr]

    @property
    def _read_ssl(self) -> Callable[[int], Optional[bytes]]:
        return partial(m2.bio_read, self.sslBio._ptr())  # type: ignore[union-attr]

    @property
    def _read_net(self) -> Callable[[int], Optional[bytes]]:
        return partial(m2.bio_read, self.networkBio._ptr())  # type: ignore[union-attr]

    def _encrypt(self, data: bytes = b"", clientHello: int = 0) -> bytes:
        """
        :param data:
        :param clientHello:
        :return:
        """
        encryptedData = b""
        self.data += data

        while 1:
            if (self._get_wr_guar_ssl() > 0 and self.data != b"") or clientHello:
                r = self._write_ssl(self.data)
                if r <= 0:
                    if not self._shoud_retry_ssl():
                        raise IOError(
                            (
                                "Data left to be written to {}, "
                                + "but cannot retry SSL connection!"
                            ).format(self.sslBio)
                        )
                else:
                    assert self.checked
                    self.data = self.data[r:]

            pending = self._ctrl_pend_net()
            if pending:
                d = self._read_net(pending)
                if d is not None:  # This is strange, but d can be None
                    encryptedData += d
                else:
                    assert self._shoud_retry_net()
            else:
                break
        return encryptedData

    def _decrypt(self, data: bytes = b"") -> bytes:
        self.encrypted += data
        decryptedData = b""

        while 1:
            if self._get_wr_guar_ssl() > 0 and self.encrypted != b"":
                r = self._write_net(self.encrypted)
                if r <= 0:
                    if not self._shoud_retry_net():
                        raise IOError(
                            (
                                "Data left to be written to {}, "
                                + "but cannot retry SSL connection!"
                            ).format(self.networkBio)
                        )
                else:
                    self.encrypted = self.encrypted[r:]

            pending = self._ctrl_pend_ssl()
            if pending:
                d = self._read_ssl(pending)
                if d is not None:  # This is strange, but d can be None
                    decryptedData += d
                else:
                    assert self._shoud_retry_ssl()
            else:
                break

        return decryptedData
