"""M2Crypto enhancement to xmlrpclib.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

import base64
import re

from M2Crypto import __version__ as __M2Version

from M2Crypto import SSL, httpslib, m2urllib2  # type: ignore
from typing import Callable, Optional, Union, Any, Dict, Tuple  # noqa

from xmlrpc.client import ProtocolError, Transport
from xmlrpc.client import *  # noqa


__version__ = __M2Version

HostType = Union[str, Tuple[str, Dict[str, str]]]
Marshallable = Any
SizedBufferType = Union[bytes, bytearray]


class SSL_Transport(Transport):

    user_agent = "M2Crypto_XMLRPC/%s - %s" % (
        __version__,
        Transport.user_agent,
    )

    def __init__(self, ssl_context: Optional[SSL.Context] = None, *args, **kw) -> None:
        Transport.__init__(self, *args, **kw)
        if ssl_context is None:
            self.ssl_ctx = SSL.Context()
        else:
            # FIX: Add assertion to make test_init_junk_ssl_context pass
            assert isinstance(ssl_context, SSL.Context), ssl_context
            self.ssl_ctx = ssl_context

    @staticmethod
    def splituser(host):
        """splituser('user[:passwd]@host[:port]') --> 'user[:passwd]', 'host[:port]'."""
        match = re.match("^(.*)@(.*)$", host)
        if match:
            return match.group(1, 2)
        return None, host

    @staticmethod
    def splitport(host):
        """splitport('host:port') --> 'host', 'port'."""
        match = re.match("^(.*):([0-9]*)$", host)
        if match:
            host, port = match.groups()
            if port:
                return host, port
        return host, None

    # This ignore is necessary because SizedBuffer is a private Protocol we cannot import
    # and satisfy fully at the argument level.
    def request(
        self,
        host: HostType,
        handler: str,
        request_body: SizedBufferType,  # type: ignore[override]
        verbose: int = 0,
    ) -> Tuple[Marshallable, ...]:

        # Handle username and password.
        user_passwd, host_port = self.splituser(host)
        _host, _port = self.splitport(host_port)

        _host_str = _host.decode("latin-1") if isinstance(_host, bytes) else _host

        h = httpslib.HTTPSConnection(_host_str, int(_port), ssl_context=self.ssl_ctx)  # type: ignore[call-arg]

        try:
            if verbose:
                h.set_debuglevel(1)

            h.putrequest("POST", handler)

            # required by HTTP/1.1
            h.putheader("Host", _host_str)

            # required by XML-RPC
            h.putheader("User-Agent", self.user_agent)
            h.putheader("Content-Type", "text/xml")
            h.putheader("Content-Length", str(len(request_body)))

            # Authorisation.
            if user_passwd is not None:
                auth = base64.encodebytes(user_passwd).strip()
                h.putheader("Authorization", "Basic %s" % auth.decode("ascii"))

            h.endheaders()

            if request_body:
                h.send(request_body)

            response = h.getresponse()

            host_str = host if isinstance(host, str) else str(host)

            headers_dict = dict(response.getheaders())

            if response.status != 200:
                raise ProtocolError(
                    host_str + handler,
                    response.status,
                    response.reason,
                    headers_dict,
                )

            self.verbose = verbose
            return self.parse_response(response)

        finally:
            h.close()
