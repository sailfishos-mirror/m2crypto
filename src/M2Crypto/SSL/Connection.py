"""SSL Connection aka socket

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2007 OSAF. All Rights Reserved.

Copyright 2008 Heikki Toivonen. All rights reserved.
"""

import logging
import socket
import io

from M2Crypto import BIO, Err, X509, m2, util, types as C
from .Checker import Checker, SSLVerificationError
from .Cipher import Cipher, Cipher_Stack
from .Session import Session
from .SSLError import SSLError
from .timeout import timeout as Timeout, struct_to_timeout, struct_size
from typing import (
    Callable,
    TYPE_CHECKING,
    Optional,
    Tuple,
    Union,
)

if TYPE_CHECKING:
    from .Context import Context

__all__ = [
    "Connection",
]

log = logging.getLogger(__name__)


def _serverPostConnectionCheck(*args, **kw) -> int:
    return 1


class Connection:
    """An SSL connection."""

    def __init__(
        self,
        ctx: "Context",
        sock: Optional[socket.socket] = None,
        family: int = socket.AF_INET,
    ) -> None:
        """

        :param ctx: SSL.Context
        :param sock: socket to be used
        :param family: socket family
        """
        # The Checker needs to be an instance attribute
        # and not a class attribute for thread safety reason
        self.clientPostConnectionCheck = Checker()

        self._bio_freed = False
        self.ctx = ctx
        self.ssl: C.SSL = m2.ssl_new(self.ctx.ctx)
        if sock is not None:
            self.socket = sock
        else:
            self.socket = socket.socket(family, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._fileno = self.socket.fileno()

        self._timeout: float
        timeout_val = self.socket.gettimeout()
        if timeout_val is None:
            self._timeout = -1.0
        else:
            self._timeout = timeout_val

        self.ssl_close_flag = m2.bio_noclose

        if self.ctx.post_connection_check is not None:
            self.set_post_connection_check_callback(self.ctx.post_connection_check)

        self.host: Optional[bytes] = None
        self._closed = False

    m2_bio_noclose = m2.bio_noclose

    @staticmethod
    def m2_ssl_free(ssl: C.SSL) -> None:
        m2.ssl_free(ssl)

    @staticmethod
    def m2_bio_free(bio: C.BIO) -> int:
        return m2.bio_free(bio)

    @property
    def closed(self) -> bool:
        return self._closed

    def _free_bio(self):
        """
        Free the sslbio and sockbio, and close the socket.
        """
        if not self._bio_freed:
            if getattr(self, "sslbio", None) and self.sslbio:
                self.m2_bio_free(self.sslbio)
            if getattr(self, "sockbio", None) and self.sockbio:
                self.m2_bio_free(self.sockbio)
            self.socket.close()
            self._bio_freed = True

    def __del__(self) -> None:
        if not self._closed:
            self.close()
        if self.ssl_close_flag == self.m2_bio_noclose and getattr(self, "ssl", None):
            self.m2_ssl_free(self.ssl)

    def close(self, freeBio: Optional[bool] = True) -> None:
        """
        if freeBio is true, call _free_bio
        """
        if self._closed:
            return
        self._closed = True
        m2.ssl_shutdown(self.ssl)
        if freeBio:
            self._free_bio()

    def clear(self) -> int:
        """
        If there were errors in this connection, call clear() rather
        than close() to end it, so that bad sessions will be cleared
        from cache.
        """
        return m2.ssl_clear(self.ssl)

    def set_shutdown(self, mode: int) -> None:
        """Sets the shutdown state of the Connection to mode.

        The shutdown state of an ssl connection is a bitmask of (use
        m2.SSL_* constants):

        0   No shutdown setting, yet.

        SSL_SENT_SHUTDOWN
            A "close notify" shutdown alert was sent to the peer, the
            connection is being considered closed and the session is
            closed and correct.

        SSL_RECEIVED_SHUTDOWN
            A shutdown alert was received form the peer, either a normal
            "close notify" or a fatal error.

        SSL_SENT_SHUTDOWN and SSL_RECEIVED_SHUTDOWN can be set at the
        same time.

        :param mode: set the mode bitmask.
        """
        m2.ssl_set_shutdown1(self.ssl, mode)

    def get_shutdown(self) -> int:
        """Get the current shutdown mode of the Connection."""
        return m2.ssl_get_shutdown(self.ssl)

    def bind(self, addr: util.AddrType) -> None:
        self.socket.bind(addr)

    def listen(self, qlen: int = 5) -> None:
        self.socket.listen(qlen)

    def ssl_get_error(self, ret: int) -> int:
        return m2.ssl_get_error(self.ssl, ret)

    def set_bio(self, readbio: BIO.BIO, writebio: BIO.BIO) -> None:
        """Explicitly set read and write bios

        Connects the BIOs for the read and write operations of the
        TLS/SSL (encrypted) side of ssl.

        The SSL engine inherits the behaviour of both BIO objects,
        respectively. If a BIO is non-blocking, the Connection will also
        have non-blocking behaviour.

        If there was already a BIO connected to Connection, BIO_free()
        will be called (for both the reading and writing side, if
        different).

        :param readbio: BIO for reading
        :param writebio: BIO for writing.
        """
        m2.ssl_set_bio(self.ssl, readbio._ptr(), writebio._ptr())

    def set_client_CA_list_from_file(self, cafile: str) -> None:
        """Set the acceptable client CA list.

        If the client returns a certificate, it must have been issued by
        one of the CAs listed in cafile.

        Makes sense only for servers.

        :param cafile: Filename from which to load the CA list.

        :return: 0 A failure while manipulating the STACK_OF(X509_NAME)
                   object occurred or the X509_NAME could not be
                   extracted from cacert. Check the error stack to find
                   out the reason.

                 1 The operation succeeded.
        """
        m2.ssl_set_client_CA_list_from_file(self.ssl, cafile)

    def set_client_CA_list_from_context(self) -> None:
        """
        Set the acceptable client CA list. If the client
        returns a certificate, it must have been issued by
        one of the CAs listed in context.

        Makes sense only for servers.
        """
        m2.ssl_set_client_CA_list_from_context(self.ssl, self.ctx.ctx)

    def setup_addr(self, addr: util.AddrType) -> None:
        self.addr = addr

    def set_ssl_close_flag(self, flag: int) -> None:
        """
        By default, SSL struct will be freed in __del__. Call with
        m2.bio_close to override this default.

        :param flag: either m2.bio_close or m2.bio_noclose
        """
        if flag not in (m2.bio_close, m2.bio_noclose):
            raise ValueError("flag must be m2.bio_close or m2.bio_noclose")
        self.ssl_close_flag = flag

    def setup_ssl(self) -> None:
        # Make a BIO_s_socket.
        self.sockbio = m2.bio_new_socket(self.socket.fileno(), 0)
        # Link SSL struct with the BIO_socket.
        m2.ssl_set_bio(self.ssl, self.sockbio, self.sockbio)
        # Make a BIO_f_ssl.
        self.sslbio = m2.bio_new(m2.bio_f_ssl())
        # Link BIO_f_ssl with the SSL struct.
        m2.bio_set_ssl(self.sslbio, self.ssl, m2.bio_noclose)

    def _setup_ssl(self, addr: util.AddrType) -> None:
        """Deprecated"""
        self.setup_addr(addr)
        self.setup_ssl()

    def set_accept_state(self) -> None:
        """Sets Connection to work in the server mode."""
        m2.ssl_set_accept_state(self.ssl)

    def accept_ssl(self) -> Optional[int]:
        """Waits for a TLS/SSL client to initiate the TLS/SSL handshake.

        The communication channel must already have been set and
        assigned to the ssl by setting an underlying BIO.

        :return: 0 The TLS/SSL handshake was not successful but was shut
                   down controlled and by the specifications of the
                   TLS/SSL protocol. Call get_error() with the return
                   value ret to find out the reason.

                 1 The TLS/SSL handshake was successfully completed,
                   a TLS/SSL connection has been established.

                 <0 The TLS/SSL handshake was not successful because
                    a fatal error occurred either at the protocol level
                    or a connection failure occurred. The shutdown was
                    not clean. It can also occur of action is need to
                    continue the operation for non-blocking BIOs. Call
                    get_error() with the return value ret to find
                    out the reason.
        """
        return m2.ssl_accept(self.ssl, self._timeout)

    def accept(self) -> Tuple["Connection", util.AddrType]:
        """Accept an SSL connection.

        The return value is a pair (ssl, addr) where ssl is a new SSL
        connection object and addr is the address bound to the other end
        of the SSL connection.

        :return: tuple of Connection and addr. Address can take very
                 various forms (see socket documentation), for IPv4 it
                 is tuple(str, int), for IPv6 a tuple of four (host,
                 port, flowinfo, scopeid), where the last two are
                 optional ints.
        """
        sock, addr = self.socket.accept()
        ssl = Connection(self.ctx, sock)
        ssl.addr = addr
        ssl.setup_ssl()
        ssl.set_accept_state()
        ssl.accept_ssl()
        check = getattr(
            self,
            "serverPostConnectionCheck",
            _serverPostConnectionCheck,
        )
        if check is not None:
            if self.host is not None:
                hostname = (
                    self.host
                    if isinstance(self.host, str)
                    else self.host.decode("utf-8")
                )
            else:
                hostname = self.addr[0]

            if not check(ssl.get_peer_cert(), hostname):
                raise SSLVerificationError("post connection check failed")
        return ssl, addr

    def set_connect_state(self) -> None:
        """Sets Connection to work in the client mode."""
        m2.ssl_set_connect_state(self.ssl)

    def connect_ssl(self) -> Optional[int]:
        return m2.ssl_connect(self.ssl, self._timeout)

    def connect(self, addr: util.AddrType) -> Optional[int]:
        """Overloading socket.connect()

        :param addr: addresses have various depending on their type

        :return:status of ssl_connect()
        """
        self.socket.connect(addr)
        self.addr = addr
        self.setup_ssl()
        self.set_connect_state()
        ret = self.connect_ssl()
        check = getattr(
            self,
            "postConnectionCheck",
            self.clientPostConnectionCheck,
        )
        if check is not None:
            peer_cert = self.get_peer_cert()

            if self.host is not None:
                hostname = (
                    self.host
                    if isinstance(self.host, str)
                    else self.host.decode("utf-8")
                )
            else:
                hostname = self.addr[0]

            if not check(peer_cert, hostname):
                raise SSLVerificationError("post connection check failed")
        return ret

    def shutdown(self, how: int) -> None:
        m2.ssl_set_shutdown1(self.ssl, how)

    def renegotiate(self) -> int:
        """Renegotiate this connection's SSL parameters."""
        return m2.ssl_renegotiate(self.ssl)

    def pending(self) -> int:
        """Return the numbers of octets that can be read from the connection."""
        return m2.ssl_pending(self.ssl)

    def write(self, data: bytes) -> int:
        return m2.ssl_write(self.ssl, data, self._timeout)

    sendall = send = write

    def _decref_socketios(self):
        pass

    def recv_into(self, buff: Union[bytearray, memoryview], nbytes: int = 0) -> int:
        """
        A version of recv() that stores its data into a buffer
        rather than creating a new string.  Receive up to nbytes
        bytes from the socket.  If nbytes is not specified (or
        0), receive up to the size available in the given buffer.

        If buff is bytearray, it will have after return length of the
        actually returned number of bytes. If buff is memoryview, then
        the size of buff won't change (it cannot), but all bytes after
        the number of returned bytes will be NULL.

        :param buffer: a buffer for the received bytes
        :param nbytes: maximum number of bytes to read
        :return: number of bytes read

        See recv() for documentation about the flags.
        """
        n = len(buff) if nbytes == 0 else nbytes

        if n <= 0:
            raise ValueError("recv_into: size of buffer must be > 0")

        # buff_bytes are actual bytes returned
        buff_bytes = m2.ssl_read(self.ssl, n, self._timeout)
        if buff_bytes is None:
            return 0
        buflen = len(buff_bytes)

        # memoryview type has been added in 2.7
        if isinstance(buff, memoryview):
            buff[:buflen] = buff_bytes
            buff[buflen:] = b"\x00" * (len(buff) - buflen)
        else:
            buff[:] = buff_bytes

        return buflen

    def read(self, size: int = 1024) -> bytes:
        if size <= 0:
            raise ValueError("size <= 0")
        ret: Optional[bytes] = m2.ssl_read(self.ssl, size, self._timeout)
        return ret if ret is not None else b""

    recv = read

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return True

    def readinto(self, b: bytearray) -> int:
        return self.recv_into(b)

    def flush(self) -> None:
        pass

    def setblocking(self, mode: int) -> None:
        """Set this connection's underlying socket to _mode_.

        Set blocking or non-blocking mode of the socket: if flag is 0,
        the socket is set to non-blocking, else to blocking mode.
        Initially all sockets are in blocking mode. In non-blocking mode,
        if a recv() call doesn't find any data, or if a send() call can't
        immediately dispose of the data, a error exception is raised;
        in blocking mode, the calls block until they can proceed.
        s.setblocking(0) is equivalent to s.settimeout(0.0);
        s.setblocking(1) is equivalent to s.settimeout(None).

        :param mode: new mode to be set
        """
        self.socket.setblocking(bool(mode))
        if mode:
            self._timeout = -1.0
        else:
            self._timeout = 0.0

    def settimeout(self, timeout: float) -> None:
        """Set this connection's underlying socket's timeout to _timeout_."""
        self.socket.settimeout(timeout)
        if timeout is None:
            self._timeout = -1.0
        else:
            self._timeout = timeout

    def fileno(self) -> int:
        return self.socket.fileno()

    def getsockopt(
        self, level: int, optname: int, buflen: Optional[int] = None
    ) -> Union[int, bytes]:
        """Get the value of the given socket option.

        :param level: level at which the option resides.
               To manipulate options at the sockets API level, level is
               specified as socket.SOL_SOCKET. To manipulate options at
               any other level the protocol number of the appropriate
               protocol controlling the option is supplied. For example,
               to indicate that an option is to be interpreted by the
               TCP protocol, level should be set to the protocol number
               of socket.SOL_TCP; see getprotoent(3).

        :param optname: The value of the given socket option is
               described in the Unix man page getsockopt(2)). The needed
               symbolic constants (SO_* etc.) are defined in the socket
               module.

        :param buflen: If it is absent, an integer option is assumed
               and its integer value is returned by the function. If
               buflen is present, it specifies the maximum length of the
               buffer used to receive the option in, and this buffer is
               returned as a bytes object.

        :return: Either integer or bytes value of the option. It is up
                 to the caller to decode the contents of the buffer (see
                 the optional built-in module struct for a way to decode
                 C structures encoded as byte strings).
        """
        if buflen is None:
            return self.socket.getsockopt(level, optname)
        else:
            return self.socket.getsockopt(level, optname, buflen)

    def setsockopt(
        self,
        level: int,
        optname: int,
        value: Union[int, bytes, None] = None,
    ) -> Optional[bytes]:
        """Set the value of the given socket option.

        :param level: same as with getsockopt() above

        :param optname: same as with getsockopt() above

        :param value: an integer or a string representing a buffer. In
                      the latter case it is up to the caller to ensure
                      that the string contains the proper bits (see the
                      optional built-in module struct for a way to
                      encode C structures as strings).

        :return: None for success or the error handler for failure.
        """
        if value is None:
            raise TypeError("value must not be None for setsockopt")
        return self.socket.setsockopt(level, optname, value)

    def get_context(self) -> "Context":
        """Return the Context object associated with this connection."""
        return self.ctx

    def get_state(self) -> str:
        """Return the SSL state of this connection.

        During its use, an SSL objects passes several states. The state
        is internally maintained. Querying the state information is not
        very informative before or when a connection has been
        established. It however can be of significant interest during
        the handshake.

        :return: 6 letter string indicating the current state of the SSL
                 object ssl.
        """
        return m2.ssl_get_state(self.ssl)

    def verify_ok(self) -> bool:
        return m2.ssl_get_verify_result(self.ssl) == m2.X509_V_OK

    def get_verify_mode(self) -> int:
        """Return the peer certificate verification mode."""
        return m2.ssl_get_verify_mode(self.ssl)

    def get_verify_depth(self) -> int:
        """Return the peer certificate verification depth."""
        return m2.ssl_get_verify_depth(self.ssl)

    def get_verify_result(self) -> int:
        """Return the peer certificate verification result."""
        return m2.ssl_get_verify_result(self.ssl)

    def get_peer_cert(self) -> Optional[X509.X509]:
        """Return the peer certificate.

        If the peer did not provide a certificate, return None.
        """
        c = m2.ssl_get_peer_cert(self.ssl)
        if c is None:
            return None
        # Need to free the pointer coz OpenSSL doesn't.
        return X509.X509(c, 1)

    def get_peer_cert_chain(self) -> Optional[X509.X509_Stack]:
        """Return the peer certificate chain; if the peer did not provide
        a certificate chain, return None.

        :warning: The returned chain will be valid only for as long as the
                  connection object is alive. Once the connection object
                  gets freed, the chain will be freed as well.
        """
        c = m2.ssl_get_peer_cert_chain(self.ssl)
        if c is None:
            return None
        # No need to free the pointer coz OpenSSL does.
        return X509.X509_Stack(c)

    def get_cipher(self) -> Optional[Cipher]:
        """Return an M2Crypto.SSL.Cipher object for this connection; if the
        connection has not been initialised with a cipher suite, return None.
        """
        c = m2.ssl_get_current_cipher(self.ssl)
        if c is None:
            return None
        return Cipher(c, _pyfree=1)

    def get_ciphers(self) -> Optional[Cipher_Stack]:
        """Return an M2Crypto.SSL.Cipher_Stack object for this
        connection; if the connection has not been initialised with
        cipher suites, return None.
        """
        c = m2.ssl_get_ciphers(self.ssl)
        if c is None:
            return None
        return Cipher_Stack(c, _pyfree=1)

    def get_cipher_list(self, idx: int = 0) -> str:
        """Return the cipher suites for this connection as a string object."""
        return m2.ssl_get_cipher_list(self.ssl, idx)

    def set_cipher_list(self, cipher_list: str) -> int:
        """Set the cipher suites for this connection."""
        return m2.ssl_set_cipher_list(self.ssl, cipher_list)

    def makefile(
        self, mode: str = "rb", bufsize: int = -1
    ) -> Union[io.BufferedRWPair, io.BufferedReader, io.BufferedWriter]:
        if "b" not in mode:
            raise ValueError("makefile requires binary mode")
        if bufsize < 0:
            bufsize = io.DEFAULT_BUFFER_SIZE
        if "w" in mode and "r" in mode:
            return io.BufferedRWPair(self, self, buffer_size=bufsize)  # type: ignore[call-arg,arg-type]
        elif "w" in mode:
            return io.BufferedWriter(self, buffer_size=bufsize)  # type: ignore[call-arg,arg-type]
        elif "r" in mode:
            return io.BufferedReader(self, buffer_size=bufsize)  # type: ignore[call-arg,arg-type]
        else:
            raise ValueError("Invalid mode: %s" % mode)

    def getsockname(self) -> util.AddrType:
        """Return the socket's own address.

        This is useful to find out the port number of an IPv4/v6 socket,
        for instance. The format of the address returned depends
        on the address family -- see above.)

        :return:socket's address as addr type
        """
        return self.socket.getsockname()

    def getpeername(self) -> util.AddrType:
        """Return the remote address to which the socket is connected.

        This is useful to find out the port number of a remote IPv4/v6 socket,
        for instance.
        On some systems this function is not supported.

        :return:
        """
        return self.socket.getpeername()

    def set_session_id_ctx(self, id: bytes) -> int:
        ret: int = m2.ssl_set_session_id_context(self.ssl, id)
        if not ret:
            raise SSLError(Err.get_error_message())
        return ret

    def get_session(self) -> Optional[Session]:
        sess = m2.ssl_get_session(self.ssl)
        if sess is None:
            return None
        return Session(sess, _pyfree=1)  # type: ignore[arg-type]

    def set_session(self, session: Session) -> None:
        m2.ssl_set_session(self.ssl, session.session)  # type: ignore[arg-type]

    def get_default_session_timeout(self) -> int:
        return m2.ssl_get_default_session_timeout(self.ssl)

    def get_socket_read_timeout(self) -> Timeout:
        return struct_to_timeout(
            self.socket.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_RCVTIMEO,
                struct_size(),
            )
        )

    def get_socket_write_timeout(self) -> Timeout:
        binstr = self.socket.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_SNDTIMEO,
            struct_size(),  # type: ignore[attr-defined]
        )
        timeo = struct_to_timeout(binstr)  # type: ignore[attr-defined]
        # print("Debug: get_socket_write_timeout: "
        #       "get sockopt value: %s -> ret timeout(sec=%r, microsec=%r)" %
        #       (self._hexdump(binstr), timeo.sec, timeo.microsec))
        return timeo

    def set_socket_read_timeout(self, timeo: Timeout) -> None:
        assert isinstance(timeo, Timeout)  # type: ignore[attr-defined]
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeo.pack())

    def set_socket_write_timeout(self, timeo: Timeout) -> None:
        assert isinstance(timeo, Timeout)  # type: ignore[attr-defined]
        binstr = timeo.pack()
        # print("Debug: set_socket_write_timeout: "
        #       "input timeout(sec=%r, microsec=%r) -> set sockopt value: %s" %
        #       (timeo.sec, timeo.microsec, self._hexdump(binstr)))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, binstr)

    def get_version(self) -> str:
        """Return the TLS/SSL protocol version for this connection."""
        return m2.ssl_get_version(self.ssl)

    def set_post_connection_check_callback(
        self, postConnectionCheck: Callable
    ) -> None:  # noqa
        self.postConnectionCheck = postConnectionCheck

    def set_tlsext_host_name(self, name: str) -> None:
        """Set the requested hostname for the SNI (Server Name Indication)
        extension.
        """
        m2.ssl_set_tlsext_host_name(self.ssl, name)

    def set1_host(self, name: bytes) -> None:
        """Set the requested hostname to check in the server certificate."""
        self.host = name
