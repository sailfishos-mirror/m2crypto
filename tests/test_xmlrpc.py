"""Unit tests for M2Crypto.m2xmlrpclib.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved.
Portions copyright (c) 2005-2006 Vrije Universiteit Amsterdam. All
rights reserved.
"""

import base64
from unittest.mock import patch, MagicMock

from M2Crypto import SSL, Rand

from M2Crypto.m2xmlrpclib import SSL_Transport
from xmlrpc.client import ProtocolError, Transport

from tests import unittest


# A valid minimal XML-RPC success response for mock
VALID_XML_RESPONSE = b"<methodResponse><params><param><value><string>OK</string></value></param></params></methodResponse>"


# Create a mock for the full response object expected from h.getresponse()
class MockResponse:
    def __init__(self, status, reason, headers, content=b""):
        self.status = status
        self.reason = reason
        self._headers = headers
        self._content = content
        self._read_queue = [content, b""]

    def getheaders(self):
        """Returns headers as a list of (name, value) tuples."""
        return self._headers

    def read(self, size=None):
        """Implements reading the response body using a side effect queue."""
        # FIX: Ensure b'' is returned after content is consumed
        if self._read_queue:
            return self._read_queue.pop(0)
        return b""  # Return empty bytes if the queue is exhausted

    def close(self):
        pass

    def geturl(self):
        # Required by xmlrpc.client.Transport.parse_response
        return "https://mockhost/RPC2"


# Class for tests that DO NOT require patching
class SSLTransportInitTests(unittest.TestCase):

    def setUp(self):
        """Set up a custom SSL context for testing."""
        self.custom_ctx = SSL.Context()
        self.assertIsNotNone(self.custom_ctx)

    def test_init_default_ssl_context(self):
        """Test instantiation with no SSL context provided."""
        t = SSL_Transport()
        self.assertIsInstance(t, SSL_Transport)
        self.assertIsInstance(t.ssl_ctx, SSL.Context)
        self.assertIsInstance(t, Transport)
        self.assertTrue(t.user_agent.startswith("M2Crypto_XMLRPC/"))

    def test_init_custom_ssl_context(self):
        """Test instantiation with a custom SSL context."""
        t = SSL_Transport(ssl_context=self.custom_ctx)
        self.assertIs(t.ssl_ctx, self.custom_ctx)

    def test_init_junk_ssl_context(self):
        """Test instantiation with an invalid type for ssl_context."""
        with self.assertRaises(AssertionError):
            SSL_Transport(ssl_context=object())

        # Test basic TypeError for positional args outside of SSL context
        with self.assertRaises(AssertionError):
            SSL_Transport("junk_arg")


# Class for tests that DO require patching
@patch("M2Crypto.m2xmlrpclib.m2urllib2")
@patch("M2Crypto.httpslib.HTTPSConnection")
class SSLTransportRequestTests(unittest.TestCase):

    def setUp(self):
        """Set up a custom SSL context for testing."""
        self.custom_ctx = SSL.Context()
        self.assertIsNotNone(self.custom_ctx)
        self.t = SSL_Transport(ssl_context=self.custom_ctx)
        self.request_body = b"<methodCall><methodName>test</methodName></methodCall>"
        self.host_url = "example.com:443"
        self.handler = "/RPC2"

    def test_request_basic_success(self, MockConn, mock_m2urllib2):
        """Test successful request with basic setup and correct response parsing."""

        mock_m2urllib2.splituser.return_value = (None, self.host_url)
        mock_m2urllib2.splitport.return_value = ("example.com", "443")

        mock_conn_instance = MockConn.return_value
        mock_conn_instance.getresponse.return_value = MockResponse(
            status=200,
            reason="OK",
            headers=[("Content-Length", str(len(VALID_XML_RESPONSE)))],
            content=VALID_XML_RESPONSE,
        )

        result = self.t.request(
            host=self.host_url,
            handler=self.handler,
            request_body=self.request_body,
            verbose=0,
        )

        MockConn.assert_called_once_with("example.com", 443, ssl_context=self.t.ssl_ctx)
        mock_conn_instance.putrequest.assert_called_once_with("POST", self.handler)
        mock_conn_instance.send.assert_called_once_with(self.request_body)
        mock_conn_instance.close.assert_called_once()
        self.assertIsInstance(result, tuple)

    def test_request_with_basic_auth(self, MockConn, mock_m2urllib2):
        """Test request includes Authorization header when credentials are provided."""

        with patch(
            "M2Crypto.m2xmlrpclib.SSL_Transport.splitport"
        ) as mock_splitport, patch(
            "M2Crypto.m2xmlrpclib.SSL_Transport.splituser"
        ) as mock_splituser:

            user_pass_bytes = b"user:secret"
            host_url_auth = "user:secret@authhost.com:8000"

            mock_splituser.return_value = (user_pass_bytes, "authhost.com:8000")
            mock_splitport.return_value = ("authhost.com", "8000")

            mock_conn_instance = MockConn.return_value
            mock_conn_instance.getresponse.return_value = MockResponse(
                status=200,
                reason="OK",
                headers=[],
                content=VALID_XML_RESPONSE,  # FIX: Use clean XML
            )

            self.t.request(
                host=host_url_auth,
                handler=self.handler,
                request_body=self.request_body,
                verbose=0,
            )

            expected_auth_val = (
                base64.encodebytes(user_pass_bytes).strip().decode("ascii")
            )
            mock_conn_instance.putheader.assert_any_call(
                "Authorization", f"Basic {expected_auth_val}"
            )
            mock_conn_instance.close.assert_called_once()

    def test_request_http_error(self, MockConn, mock_m2urllib2):
        """Test request raises ProtocolError on non-200 HTTP status."""

        with patch(
            "M2Crypto.m2xmlrpclib.SSL_Transport.splituser"
        ) as mock_splituser, patch(
            "M2Crypto.m2xmlrpclib.SSL_Transport.splitport"
        ) as mock_splitport:

            mock_splituser.return_value = (None, self.host_url)
            mock_splitport.return_value = ("example.com", "443")

            mock_conn_instance = MockConn.return_value
            error_headers = [("Connection", "close"), ("X-Error", "Auth-Failed")]
            mock_conn_instance.getresponse.return_value = MockResponse(
                status=404,
                reason="Not Found",
                headers=error_headers,
                content=b"<html>Not Found</html>",
            )

            with self.assertRaises(ProtocolError) as cm:
                self.t.request(
                    host=self.host_url,
                    handler="/MISSING",
                    request_body=b"<body>",
                    verbose=0,
                )

            self.assertEqual(cm.exception.errcode, 404)

            mock_conn_instance.close.assert_called_once()


def suite():
    """Returns a unittest.TestSuite object for the module's tests."""
    loader = unittest.TestLoader()
    return unittest.TestSuite(
        [
            loader.loadTestsFromTestCase(SSLTransportInitTests),
            loader.loadTestsFromTestCase(SSLTransportRequestTests),
        ]
    )


if __name__ == "__main__":
    Rand.load_file("randpool.dat", -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file("randpool.dat")
