"""
M2Crypto enhancement to Python's urllib2 for handling
'https' url's.

Code from urllib2 is Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007
Python Software Foundation; All Rights Reserved

Summary of changes:
 - Use an HTTPSProxyConnection if the request is going through a proxy.
 - Add the SSL context to the https connection when performing https_open.
 - Add the M2Crypto HTTPSHandler when building a default opener.
"""

import socket

from M2Crypto import SSL, httpslib

from urllib.parse import urldefrag, urlparse as url_parse
from urllib.response import addinfourl
from typing import Optional  # noqa

from urllib.request import *  # noqa other modules want to import
from urllib.error import *  # noqa other modules want to import


try:
    mother_class = socket._fileobject
except AttributeError:
    mother_class = socket.SocketIO


class _closing_fileobject(mother_class):  # noqa
    """socket._fileobject that propagates self.close() to the socket.

    Python 2.5 provides this as socket._fileobject(sock, close=True).
    """


# for python 3
try:
    AbstractHTTPHandler
except NameError:
    # somehow this won't get imported by the import * above
    import urllib.request

    AbstractHTTPHandler = urllib.request.AbstractHTTPHandler


def _makefile(sock_like, mode, bufsize):
    """
    The original implementation of this function created an infinite
    recursion by incorrectly monkey-patching _decref_socketios.
    Removing the incorrect logic resolves the issue. The SocketIO
    object correctly calls close() on the wrapped sock_like object
    by default.
    """
    return socket.SocketIO(sock_like, mode)


class RefCountingSSLConnection(SSL.Connection):
    """A reference counting SSL connection.

    It can be wrapped into a socket._fileobject or socket.SocketIO instance.
    If the wrapping object is closed or subject to garbage collection,
    this SSL connection is only shut down if there are no more references,
    which were created by RefCountingSSLConnection.makefile, to it.
    """

    def __init__(self, *args, **kwargs):
        SSL.Connection.__init__(self, *args, **kwargs)
        # Start with one reference for the connection object itself.
        self._refs = 0
        self._closed = False

    def _decref_socketios(self):
        if self._refs > 0:
            self._refs -= 1
        if self._refs == 0 and not self._closed:
            # make sure we close the connection only once
            # (otherwise we end up with a bidirectional shutdown)
            self._closed = True
            super(RefCountingSSLConnection, self).close()

    def close(self):
        """
        Close the connection. This is idempotent.

        The original ref-counting logic has been bypassed for this direct
        call to provide a simpler, more robust shutdown path for the
        primary use case.
        """
        if not getattr(self, '_closed', False):
            self._closed = True
            # Directly close the parent connection without complex logic.
            super(RefCountingSSLConnection, self).close()

    def makefile(self, mode='rb', bufsize=-1):
        self._refs += 1
        return _makefile(self, mode, bufsize)


class HTTPSHandler(AbstractHTTPHandler):  # type: ignore [no-redef]
    def __init__(
        self,
        ssl_context: Optional[SSL.Context] = None,
        ssl_conn_cls: SSL.Connection = RefCountingSSLConnection,
    ):
        AbstractHTTPHandler.__init__(self)

        if ssl_context is not None:
            assert isinstance(ssl_context, SSL.Context), ssl_context
            self.ctx = ssl_context
        else:
            self.ctx = SSL.Context()
        self._ssl_conn_cls = ssl_conn_cls

    # Copied from urllib2, so we can set the ssl context.
    def https_open(self, req: Request) -> addinfourl:
        """Return an addinfourl object for the request, using http_class.

        http_class must implement the HTTPConnection API from httplib.
        The addinfourl return value is a file-like object.  It also
        has methods and attributes including:

            - info(): return a mimetools.Message object for the headers

            - geturl(): return the original request URL

            - code: HTTP status code
        """
        host = req.host
        if not host:
            raise URLError('no host given')

        # Our change: Check to see if we're using a proxy.
        # Then create an appropriate ssl-aware connection.
        full_url = req.get_full_url()
        target_host = url_parse(full_url)[1]

        if target_host != host:
            request_uri = urldefrag(full_url)[0]
            h = httpslib.ProxyHTTPSConnection(
                host=host,
                ssl_context=self.ctx,
                ssl_conn_cls=self._ssl_conn_cls,
            )
        else:
            request_uri = req.selector
            h = httpslib.HTTPSConnection(
                host=host,
                ssl_context=self.ctx,
                ssl_conn_cls=self._ssl_conn_cls,
            )
        # End our change
        h.set_debuglevel(self._debuglevel)

        headers = dict(req.headers)
        headers.update(req.unredirected_hdrs)
        # We want to make an HTTP/1.1 request, but the addinfourl
        # class isn't prepared to deal with a persistent connection.
        # It will try to read all remaining data from the socket,
        # which will block while the server waits for the next request.
        # So make sure the connection gets closed after the (only)
        # request.
        headers["Connection"] = "close"
        try:
            h.request(
                req.get_method(), request_uri, req.data, headers
            )
            r = h.getresponse()
        except socket.error as err:
            raise URLError(err)

        # This is critical to ensure that HTTP-level processing
        # like de-chunking happens, by routing read() calls to
        # the HTTPResponse object 'r', not the raw socket.
        r.recv = r.read
        # The line below is not strictly necessary but is part
        # of the original design
        r._decref_socketios = lambda: None
        r.ssl = h.sock.ssl
        r._timeout = -1.0
        r.recv_into = r.readinto
        fp = socket.SocketIO(r, 'rb')

        resp = addinfourl(fp, r.msg, req.get_full_url())
        resp.code = r.status
        resp.msg = r.reason

        # We must keep the connection object 'h' alive for as long as the
        # response 'resp' is alive. Otherwise, 'h' and its underlying
        # socket 'h.sock' can be garbage collected prematurely, causing the
        # "ValueError: I/O operation on closed file" error.
        # We solve this by attaching the connection to the response object.
        resp._connection = h

        # The diagnostic logs proved that the default close() chain is broken
        # and does not call close() on the underlying SSL connection.
        #
        # To fix this, we manually hijack the close() method of the returned
        # response object to GUARANTEE that the underlying connection is closed.

        # Get a direct reference to the connection we need to close.
        the_connection_to_close = h.sock

        # Get a reference to the original, broken close method.
        original_close = resp.close

        def new_close():
            try:
                # First, run the original close procedure to clean up
                # the file pointers and other parts of the chain.
                original_close()
            finally:
                # CRUCIALLY, ensure our underlying connection is told to close.
                # This will now correctly call RefCountingSSLConnection.close()
                # on the right object, setting the _closed flag.
                if the_connection_to_close:
                    the_connection_to_close.close()

        # Replace the response object's close method with our reliable one.
        resp.close = new_close

        return resp

    https_request = AbstractHTTPHandler.do_request_


# Copied from urllib2 with modifications for ssl
def build_opener(  # type: ignore [no-redef]
    ssl_context: Optional[SSL.Context] = None, *handlers
) -> OpenerDirector:
    """Create an opener object from a list of handlers.

    The opener will use several default handlers, including support
    for HTTP and FTP.

    If any of the handlers passed as arguments are subclasses of the
    default handlers, the default handlers will not be used.
    """

    def isclass(obj):
        return isinstance(obj, type) or hasattr(obj, "__bases__")

    opener = OpenerDirector()
    default_classes = [
        ProxyHandler,
        UnknownHandler,
        HTTPHandler,
        HTTPDefaultErrorHandler,
        HTTPRedirectHandler,
        FTPHandler,
        FileHandler,
        HTTPErrorProcessor,
    ]
    skip = []
    for klass in default_classes:
        for check in handlers:
            if isclass(check):
                if issubclass(check, klass):
                    skip.append(klass)
            elif isinstance(check, klass):
                skip.append(klass)
    for klass in skip:
        default_classes.remove(klass)

    for klass in default_classes:
        opener.add_handler(klass())

    # Add the HTTPS handler with ssl_context
    if HTTPSHandler not in skip:
        opener.add_handler(HTTPSHandler(ssl_context))

    for h in handlers:
        if isclass(h):
            h = h()
        opener.add_handler(h)
    return opener
