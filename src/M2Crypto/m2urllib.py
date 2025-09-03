"""M2Crypto enhancement to Python's urllib for handling
'https' url's.

FIXME: it is questionable whether we need this old-style module at all. urllib
(not urllib2) is in Python 3 support just as a legacy API.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

import base64
import warnings

from M2Crypto import SSL, httpslib

from urllib.response import addinfourl
from typing import Optional, Union  # noqa

from urllib.request import *  # noqa for other modules to import
from urllib.parse import *  # noqa for other modules to import
from urllib.error import *  # noqa for other modules to import

if "URLopener" in globals():

    def open_https(
        self: URLopener,
        url: Union[str, bytes],
        data: Optional[bytes] = None,
        ssl_context: Optional[SSL.Context] = None,
    ) -> addinfourl:
        """
        Open URL over the SSL connection.

        :param url: URL to be opened
        :param data: data for the POST request
        :param ssl_context: SSL.Context to be used
        :return:
        """
        warnings.warn("URLOpener has been deprecated in Py3k", DeprecationWarning)

        # Dynamically add the SSL context to the URLopener instance.
        context: SSL.Context
        if ssl_context is not None and isinstance(ssl_context, SSL.Context):
            context = ssl_context
        else:
            context = SSL.Context()

        self.ctx = context  # type: ignore[attr-defined]

        # Normalize the URL to a string for robust parsing.
        url_str = url.decode("latin-1") if isinstance(url, bytes) else url

        parsed = urlparse(url_str)
        if parsed.scheme.lower() != "https":
            raise IOError("url error", "invalid URL scheme")

        host = parsed.hostname
        if not host:
            raise IOError("http error", "no host given")

        # Build the host:port string for the connection.
        host_port = host
        if parsed.port:
            host_port += f":{parsed.port}"

        # Reconstruct the path and query part of the URL.
        selector = urlunsplit(("", "", parsed.path, parsed.query, parsed.fragment))
        if not selector:
            selector = "/"

        # Handle authentication from the URL.
        auth_header_value = None
        if parsed.username:
            user_pass = parsed.username
            if parsed.password:
                user_pass += f":{parsed.password}"
            # base64.encodebytes requires bytes and returns bytes.
            auth_bytes = base64.encodebytes(user_pass.encode("utf-8")).strip()
            # The final header value must be a string.
            auth_header_value = f'Basic {auth_bytes.decode("ascii")}'

        # Mypy gets confused by our re-defined HTTPSConnection.
        h = httpslib.HTTPSConnection(
            host=host_port, ssl_context=context
        )  # type: ignore[call-arg]

        if data is not None:
            h.putrequest("POST", selector)
            h.putheader("Content-type", "application/x-www-form-urlencoded")
            h.putheader("Content-length", str(len(data)))
        else:
            h.putrequest("GET", selector)

        if auth_header_value:
            h.putheader("Authorization", auth_header_value)

        # URLopener stores extra headers in `addheaders`.
        for header, value in self.addheaders:  # type: ignore[attr-defined]
            h.putheader(header, value)
        h.endheaders()

        if data is not None:
            h.send(data)

        # Get the response and wrap it in the expected addinfourl object.
        resp = h.getresponse()
        # Use the modern `.headers` attribute, not the deprecated `.msg`.
        return addinfourl(resp, resp.headers, "https:" + url_str)

    # Monkey-patch the method onto the (deprecated) URLopener class.
    URLopener.open_https = open_https  # type: ignore[attr-defined, method-assign, used-before-def, assignment]
else:
    import sys

    class URLopener:  # type: ignore [no-redef]
        msg = f'Python {"%d.%d" % (sys.version_info[:2])} does not support URLopener any more.'

        def __init__(self):
            raise RuntimeError(self.msg)

        def open_https(self):
            raise RuntimeError(self.msg)
