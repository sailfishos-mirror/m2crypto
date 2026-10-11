"""Unit tests for M2Crypto.SSL.Checker (peer certificate hostname checks).

Copyright (C) 2006 Open Source Applications Foundation. All Rights Reserved.

Copyright (C) 2009-2010 Heikki Toivonen. All Rights Reserved.
"""

import doctest
import sys

from M2Crypto import SSL, X509, m2
from tests import unittest
from tests.test_ssl import BaseSSLClientTestCase, srv_bind_host, srv_host

# OID 1.3.6.1.4.1.311.20.2.3 (Microsoft User Principal Name)
UPN_OID = bytes.fromhex("2b0601040182371402 03".replace(" ", ""))


def _der(tag, body):
    """Minimal DER TLV encoder, enough to build GeneralNames by hand."""
    n = len(body)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + body


def uri_name(value):
    return _der(0x86, value)


def email_name(value):
    return _der(0x81, value)


def dns_name(value):
    return _der(0x82, value)


def ip_name(octets):
    return _der(0x87, octets)


def upn_name(value):
    # otherName ::= [0] { type-id OID, value [0] EXPLICIT UTF8String }
    return _der(0xA0, _der(0x06, UPN_OID) + _der(0xA0, _der(0x0C, value)))


def make_cert(common_name=None, general_names=None):
    """Build an unsigned certificate; signing does not matter to Checker.

    general_names is a list of DER-encoded GeneralName values. They are
    put into subjectAltName verbatim, so values may contain characters
    (such as ',') that OpenSSL's text configuration syntax would split.
    """
    cert = X509.X509()
    subject = X509.X509_Name()
    if common_name is not None:
        subject.CN = common_name
    cert.set_subject(subject)
    if general_names is not None:
        san = _der(0x30, b"".join(general_names))
        cert.add_ext(X509.new_extension("subjectAltName", "DER:" + san.hex()))
    return cert


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

    def test_doctests(self):
        failures, _ = doctest.testmod(SSL.Checker, verbose=False)
        self.assertEqual(failures, 0)

    def test_match_regex_metacharacters(self):
        """Certificate names must not supply regular expression operators."""
        check = SSL.Checker.Checker()
        cases = (
            ("target.com", "target.com|attacker.com"),
            ("aaab.evil.com", "(a+)+b.evil.com"),
            ("a.evil.com", "[ab].evil.com"),
            ("a.evil.com", "a?.evil.com"),
            ("aa.evil.com", "a{2}.evil.com"),
            ("target.com", "^target.com$"),
            ("target.com", "[.attacker.com"),
            ("target.com", "(.attacker.com"),
            ("target.com", "+.attacker.com"),
        )
        for host, cert_host in cases:
            with self.subTest(host=host, cert_host=cert_host):
                self.assertFalse(check._match(host, cert_host))

    def test_checker_rejects_regex_identities(self):
        """Reject regex identities read from real X.509 CN and SAN fields."""
        for host, cert_host in (
            ("target.com", "target.com|attacker.com"),
            ("aaab.evil.com", "(a+)+b.evil.com"),
            ("target.com", "[.attacker.com"),
        ):
            for field in ("commonName", "subjectAltName"):
                with self.subTest(cert_host=cert_host, field=field):
                    cert = X509.X509()
                    subject = X509.X509_Name()
                    # A matching CN must not override a mismatched DNS SAN.
                    subject.CN = cert_host if field == "commonName" else host
                    cert.set_subject(subject)
                    if field == "subjectAltName":
                        cert.add_ext(
                            X509.new_extension("subjectAltName", "DNS:" + cert_host)
                        )
                    with self.assertRaises(SSL.Checker.WrongHost):
                        SSL.Checker.Checker()(cert, host)

    def test_match_wildcards_and_guards(self):
        """The legacy _match() helper keeps its old behaviour."""
        check = SSL.Checker.Checker()
        cases = (
            ("my.example.com", "my.example.com", True),
            ("my.example.com", "MY.EXAMPLE.COM", True),
            ("my.example.com", "*.example.com", True),
            ("my.example.com", "m*.example.com", True),
            ("my.example.com", "m*ample.com", False),
            ("my.example.com", "*.*.com", False),
            ("my.sub.example.com", "*.example.com", False),
            ("1.2.3.4", "1.2.3.4", True),
            ("1.2.3.4", "*.2.3.4", False),
            ("my.example.com", r"m\*.example.com", False),
            ("my.example.com\n", "*.example.com", False),
        )
        for host, cert_host, expected in cases:
            with self.subTest(host=host, cert_host=cert_host):
                self.assertEqual(check._match(host, cert_host), expected)


class SubjectAltNameInjectionTestCase(unittest.TestCase):
    """Non-DNS SAN values must never be read as DNS or IP identities.

    OpenSSL prints URI, email, otherName and DirName values without
    escaping ',', so splitting the printed subjectAltName on commas let a
    certificate issued for one identity match an unrelated host.
    """

    victim = b"victim.example"

    def assertRejected(self, cert, host):
        with self.assertRaises(SSL.Checker.SSLVerificationError):
            SSL.Checker.Checker()(cert, host)

    def test_uri_injection(self):
        cert = make_cert(
            "attacker.example",
            [uri_name(b"https://attacker.example/x,DNS:" + self.victim)],
        )
        self.assertIn(
            "DNS:victim.example", cert.get_ext("subjectAltName").get_value()
        )
        self.assertRejected(cert, "victim.example")

    def test_email_injection(self):
        cert = make_cert(
            "attacker.example",
            [email_name(b"a@attacker.example,DNS:" + self.victim)],
        )
        self.assertRejected(cert, "victim.example")

    def test_upn_injection(self):
        cert = make_cert(
            "attacker.example",
            [upn_name(b"user@attacker.example,DNS:" + self.victim)],
        )
        self.assertRejected(cert, "victim.example")

    def test_injection_alongside_real_dns_name(self):
        cert = make_cert(
            "attacker.example",
            [
                dns_name(b"attacker.example"),
                uri_name(b"spiffe://attacker.example/x, DNS:" + self.victim),
            ],
        )
        self.assertTrue(SSL.Checker.Checker()(cert, "attacker.example"))
        self.assertRejected(cert, "victim.example")

    def test_ip_address_injection(self):
        for payload in (
            uri_name(b"https://attacker.example/,IP Address:127.0.0.1"),
            email_name(b"a@attacker.example,IP Address:127.0.0.1"),
        ):
            with self.subTest(payload=payload):
                self.assertRejected(make_cert("attacker.example", [payload]), "127.0.0.1")


class CheckerHostMatchingTestCase(unittest.TestCase):
    def check(self, cert, host, checker=None):
        return (checker or SSL.Checker.Checker())(cert, host)

    def test_dns_san_match(self):
        cert = make_cert("ignored.example", [dns_name(b"my.example.com")])
        self.assertTrue(self.check(cert, "my.example.com"))
        self.assertTrue(self.check(cert, "MY.Example.COM"))
        self.assertTrue(self.check(cert, b"my.example.com"))

    def test_dns_san_overrides_common_name(self):
        cert = make_cert("my.example.com", [dns_name(b"other.example.com")])
        with self.assertRaises(SSL.Checker.WrongHost) as cm:
            self.check(cert, "my.example.com")
        self.assertEqual(cm.exception.fieldName, "subjectAltName")

    def test_ip_san_disables_common_name(self):
        """Legacy rule: any DNS or IP SAN means the CN is not consulted."""
        cert = make_cert("my.example.com", [ip_name(bytes([10, 0, 0, 1]))])
        with self.assertRaises(SSL.Checker.WrongHost):
            self.check(cert, "my.example.com")

    def test_wildcards(self):
        cert = make_cert(None, [dns_name(b"*.example.com")])
        self.assertTrue(self.check(cert, "my.example.com"))
        for host in ("example.com", "my.sub.example.com"):
            with self.subTest(host=host):
                with self.assertRaises(SSL.Checker.WrongHost):
                    self.check(cert, host)

    def test_partial_wildcard_rejected_by_default(self):
        cert = make_cert(None, [dns_name(b"m*.example.com")])
        with self.assertRaises(SSL.Checker.WrongHost):
            self.check(cert, "my.example.com")

        legacy = SSL.Checker.Checker()
        legacy.hostCheckFlags = 0
        self.assertTrue(self.check(cert, "my.example.com", legacy))

    def test_idn_a_label(self):
        cert = make_cert(None, [dns_name(b"xn--bcher-kva.example")])
        self.assertTrue(self.check(cert, "xn--bcher-kva.example"))
        with self.assertRaises(SSL.Checker.WrongHost):
            self.check(cert, "xn--caf-dma.example")

    def test_common_name_fallback(self):
        cert = make_cert("my.example.com")
        self.assertTrue(self.check(cert, "my.example.com"))
        with self.assertRaises(SSL.Checker.WrongHost) as cm:
            self.check(cert, "other.example.com")
        self.assertEqual(cm.exception.fieldName, "commonName")

    def test_no_identity(self):
        with self.assertRaises(SSL.Checker.WrongCertificate):
            self.check(make_cert(), "my.example.com")

    def test_ip_san(self):
        cert = make_cert(
            None,
            [
                ip_name(bytes([1, 2, 3, 4])),
                ip_name(bytes(15) + b"\x01"),
            ],
        )
        self.assertTrue(self.check(cert, "1.2.3.4"))
        self.assertTrue(self.check(cert, "::1"))
        self.assertTrue(self.check(cert, "0:0:0:0:0:0:0:1"))
        for host in ("1.2.3.40", "::2"):
            with self.subTest(host=host):
                with self.assertRaises(SSL.Checker.WrongHost):
                    self.check(cert, host)

    def test_ip_host_does_not_match_dns_san(self):
        cert = make_cert(None, [dns_name(b"1.2.3.4")])
        with self.assertRaises(SSL.Checker.WrongHost):
            self.check(cert, "1.2.3.4")

    def test_ip_common_name_fallback(self):
        """Certificates without SAN may still carry an IP in the CN."""
        self.assertTrue(self.check(make_cert("1.2.3.4"), "1.2.3.4"))
        with self.assertRaises(SSL.Checker.WrongHost):
            self.check(make_cert("1.2.3.4"), "1.2.3.5")


class SubjectAltNamesAccessorTestCase(unittest.TestCase):
    def test_types_and_values(self):
        cert = make_cert(
            None,
            [
                dns_name(b"my.example.com"),
                ip_name(bytes([1, 2, 3, 4])),
                uri_name(b"https://x.example/a,DNS:victim.example"),
                email_name(b"a@x.example"),
                upn_name(b"u@x.example"),
            ],
        )
        names = cert.get_subject_alt_names()
        self.assertEqual(
            [t for t, _ in names],
            [m2.GEN_DNS, m2.GEN_IPADD, m2.GEN_URI, m2.GEN_EMAIL, m2.GEN_OTHERNAME],
        )
        self.assertEqual(names[0][1], b"my.example.com")
        self.assertEqual(names[1][1], b"\x01\x02\x03\x04")
        self.assertEqual(names[2][1], b"https://x.example/a,DNS:victim.example")
        self.assertEqual(names[3][1], b"a@x.example")
        self.assertEqual(names[4][1], upn_name(b"u@x.example"))

    def test_no_san(self):
        self.assertEqual(make_cert("x").get_subject_alt_names(), [])

    def test_duplicate_san(self):
        cert = make_cert(None, [dns_name(b"a.example")])
        cert.add_ext(X509.new_extension("subjectAltName", "DNS:b.example"))
        with self.assertRaises(X509.X509Error):
            cert.get_subject_alt_names()
        with self.assertRaises(SSL.Checker.WrongCertificate):
            SSL.Checker.Checker()(cert, "a.example")


@unittest.skipIf(sys.platform == "win32", "Test doesn't work on Windows")
class CheckerSSLClientTestCase(BaseSSLClientTestCase):
    """Hostname checks during real TLS connections."""

    def setUp(self):
        super(CheckerSSLClientTestCase, self).setUp()
        self.ctx = SSL.Context()

    def tearDown(self):
        self.ctx.close()

    def start_idn_server(self):
        return self.start_server(
            [
                "s_server",
                "-www",
                "-cert",
                "idn_server.pem",
                "-accept",
                "%s:%s" % (srv_bind_host, self.srv_port),
            ]
        )

    def test_idn_hostname(self):
        idn_hostname = "xn--bcher-kva.example"
        pid = self.start_idn_server()
        try:
            self.ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 9)
            self.ctx.load_verify_locations("tests/ca.pem")
            s = SSL.Connection(self.ctx)
            s.set_tlsext_host_name(idn_hostname)
            s.set1_host(idn_hostname.encode("ascii"))
            s.connect(self.srv_addr)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn(self.test_output, data)

    def test_set1_host_mismatch_fails_handshake(self):
        """set1_host() makes OpenSSL reject the certificate in the handshake."""
        pid = self.start_idn_server()
        try:
            self.ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 9)
            self.ctx.load_verify_locations("tests/ca.pem")
            s = SSL.Connection(self.ctx)
            s.set_post_connection_check_callback(None)
            s.set1_host("victim.example")
            try:
                with self.assertRaises(SSL.SSLError):
                    s.connect(self.srv_addr)
            finally:
                s.close()
        finally:
            self.stop_server(pid)

    def test_post_connection_check_mismatch(self):
        pid = self.start_idn_server()
        try:
            self.ctx.load_verify_locations("tests/ca.pem")
            s = SSL.Connection(self.ctx)
            s.set_tlsext_host_name("victim.example")
            try:
                with self.assertRaises(SSL.Checker.WrongHost):
                    s.connect((srv_host, self.srv_port))
            finally:
                s.close()
        finally:
            self.stop_server(pid)


def suite():
    loader = unittest.TestLoader()
    t_suite = unittest.TestSuite()
    for case in (
        CheckerTestCase,
        SubjectAltNameInjectionTestCase,
        CheckerHostMatchingTestCase,
        SubjectAltNamesAccessorTestCase,
        CheckerSSLClientTestCase,
    ):
        t_suite.addTest(loader.loadTestsFromTestCase(case))
    return t_suite


if __name__ == "__main__":
    unittest.TextTestRunner().run(suite())
