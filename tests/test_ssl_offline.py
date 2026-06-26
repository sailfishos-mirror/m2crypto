"""Unit tests for M2Crypto.SSL offline parts

Copyright (C) 2006 Open Source Applications Foundation. All Rights Reserved.

Copyright (C) 2009-2010 Heikki Toivonen. All Rights Reserved.
"""

import doctest

from M2Crypto import Rand, SSL, X509, m2
from tests import unittest
from tests.test_ssl import srv_host


class CheckerTestCase(unittest.TestCase):
    def test_checker(self):

        check = SSL.Checker.Checker(
            host=srv_host,
            peerCertHash="9917962167CFDB8BCFAC775093E79A1113B3DA146EA4E1EB1FEFC6E58770D158",
        )
        x509 = X509.load_cert("tests/server.pem")
        self.assertTrue(check(x509, srv_host))
        with self.assertRaises(SSL.Checker.WrongHost):
            check(x509, "example.com")

        doctest.testmod(SSL.Checker)


class ContextTestCase(unittest.TestCase):
    def test_ctx_load_verify_locations(self):
        ctx = SSL.Context()
        with self.assertRaises(ValueError):
            ctx.load_verify_locations(None, None)

    def test_ctx_set_default_verify_paths(self):
        ctx = SSL.Context()
        ctx.set_default_verify_paths()
        # test will get here only if the previous won't fail

    def test_map(self):
        from M2Crypto.SSL.Context import ctxmap, _ctxmap

        self.assertIsInstance(ctxmap(), _ctxmap)
        ctx = SSL.Context()
        assert ctxmap()
        ctx.close()
        self.assertIs(ctxmap(), _ctxmap.singleton)

    def test_certstore(self):
        ctx = SSL.Context()
        ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 9)
        ctx.load_verify_locations("tests/ca.pem")
        ctx.load_cert("tests/x509.pem")

        store = ctx.get_cert_store()
        self.assertIsInstance(store, X509.X509_Store)

    def test_default_options_disable_legacy_protocols(self):
        """Default Context() must disable SSLv2, SSLv3, TLS 1.0 and TLS 1.1.

        Regression test for the security-audit finding that TLS 1.0 / 1.1
        were enabled by default.
        """
        # set_options(0) returns the currently-set bitmask without
        # changing it (OR-ing in zero is a no-op).
        ctx = SSL.Context()
        opts = ctx.set_options(0)
        for flag_name in (
            "SSL_OP_NO_SSLv2",
            "SSL_OP_NO_SSLv3",
            "SSL_OP_NO_TLSv1",
            "SSL_OP_NO_TLSv1_1",
        ):
            flag = getattr(m2, flag_name)
            self.assertTrue(
                opts & flag,
                "Default Context() must have %s set (mask=0x%x)" % (flag_name, opts),
            )

    def test_weak_crypto_keeps_legacy_protocols(self):
        """Context(weak_crypto=1) preserves the legacy escape hatch."""
        ctx = SSL.Context(weak_crypto=1)
        opts = ctx.set_options(0)
        # weak_crypto=1 must not gratuitously set the NO_TLSv1* bits.
        self.assertFalse(opts & m2.SSL_OP_NO_TLSv1)
        self.assertFalse(opts & m2.SSL_OP_NO_TLSv1_1)


def suite():
    t_suite = unittest.TestSuite()
    t_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(CheckerTestCase))
    t_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ContextTestCase))
    return t_suite


if __name__ == "__main__":
    Rand.load_file("randpool.dat", -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file("randpool.dat")
