#!/usr/bin/env python

"""Unit tests for M2Crypto.AuthCookie.

Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved."""

import logging
import time

from M2Crypto import EVP, Rand, util
from M2Crypto.AuthCookie import (
    AuthCookie,
    AuthCookieJar,
    mix,
    unmix,
    unmix3,
)
from http.cookies import (
    SimpleCookie,
)  # pylint: disable=no-name-in-module,import-error
from tests import unittest

log = logging.getLogger(__name__)


class AuthCookieTestCase(unittest.TestCase):

    _format = 'Set-Cookie: _M2AUTH_="exp=%f&data=%s&digest=%s"'
    _token = "_M2AUTH_"

    def setUp(self):
        self.data = "cogitoergosum"
        self.exp = time.time() + 3600
        self.jar = AuthCookieJar()

    def tearDown(self):
        pass

    @staticmethod
    def _corrupt_char(c: str) -> str:
        """Shift character within printable ASCII range (0x21-0x7e).

        Unlike the naive ``chr(ord(c) + 13)`` this avoids producing
        control characters which are rejected by ``http.cookies`` since
        the fix for CVE-2026-0672.
        """
        return chr(0x21 + (ord(c) - 0x21 + 13) % (0x7e - 0x21 + 1))

    def _corrupt_part_str(self, s: str, fr: int, to: int) -> str:
        out = s[:fr] + "".join([self._corrupt_char(x) for x in s[fr:to]]) + s[to:]
        self.assertNotEqual(s, out)
        return out

    def test_encode_part_str(self):
        a_str = "a1b2c3d4e5f6h7i8j9"
        # Characters at positions 3-5 are "2c", shifted +13 within
        # printable ASCII range (0x21-0x7e):
        # '2' = 0x32, corrupted = chr(0x21 + (0x32 - 0x21 + 13) % 94) = chr(0x21 + 30) = chr(0x3f) = '?'
        # 'c' = 0x63, corrupted = chr(0x21 + (0x63 - 0x21 + 13) % 94) = chr(0x21 + 79) = chr(0x70) = 'p'
        self.assertEqual(self._corrupt_part_str(a_str, 3, 5), "a1b?p3d4e5f6h7i8j9")

    def test_mix_unmix(self):
        dough = mix(self.exp, self.data)
        exp, data = unmix(dough)
        self.assertEqual(data, self.data)
        # we are comparing seconds here, ten-thousandth
        # second should be enough.
        self.assertAlmostEqual(exp, self.exp, places=4)

    def test_make_cookie(self):
        c = self.jar.makeCookie(self.exp, self.data)
        self.assertTrue(isinstance(c, AuthCookie))
        self.assertEqual(c.expiry(), self.exp)
        self.assertEqual(c.data(), self.data)
        # Peek inside the cookie jar...
        key = self.jar._key  # pylint: disable=protected-access
        mac = util.bin_to_hex(
            EVP.hmac(key, mix(self.exp, self.data).encode(), "sha256")
        )
        self.assertEqual(c.mac(), mac)
        # Ok, stop peeking now.
        cookie_str = self._format % (self.exp, self.data, mac)
        self.assertEqual(c.output(), cookie_str)

    def test_make_cookie_invalid(self):
        with self.assertRaises(ValueError):
            self.jar.makeCookie("complete nonsense", self.data)

    def test_expired(self):
        t = self.exp - 7200
        c = self.jar.makeCookie(t, self.data)
        self.assertTrue(c.isExpired())

    def test_not_expired(self):
        c = self.jar.makeCookie(self.exp, self.data)
        self.assertFalse(c.isExpired())

    def test_is_valid(self):
        c = self.jar.makeCookie(self.exp, self.data)
        self.assertTrue(self.jar.isGoodCookie(c))

    def test_is_invalid_expired(self):
        t = self.exp - 7200
        c = self.jar.makeCookie(t, self.data)
        self.assertFalse(self.jar.isGoodCookie(c))

    def test_is_invalid_changed_exp(self):
        c = self.jar.makeCookie(self.exp, self.data)
        c._expiry = 0  # pylint: disable=protected-access
        self.assertFalse(self.jar.isGoodCookie(c))

    def test_is_invalid_changed_data(self):
        c = self.jar.makeCookie(self.exp, self.data)
        c._data = "this is bad"  # pylint: disable=protected-access
        self.assertFalse(self.jar.isGoodCookie(c))

    def test_is_invalid_changed_mac(self):
        c = self.jar.makeCookie(self.exp, self.data)
        c._mac = "this is bad"  # pylint: disable=protected-access
        self.assertFalse(self.jar.isGoodCookie(c))

    def test_mix_unmix3(self):
        c = self.jar.makeCookie(self.exp, self.data)
        s = SimpleCookie()
        s.load(c.output(header=""))
        exp, data, digest = unmix3(s[self._token].value)
        self.assertEqual(data, self.data)
        # see comment in test_mix_unmix
        self.assertAlmostEqual(exp, self.exp, places=4)
        key = self.jar._key  # pylint: disable=protected-access
        mac = util.bin_to_hex(
            EVP.hmac(key, mix(self.exp, self.data).encode(), "sha256")
        )
        self.assertEqual(digest, mac)

    def test_cookie_str(self):
        c = self.jar.makeCookie(self.exp, self.data)
        self.assertTrue(self.jar.isGoodCookieString(c.output(header="")))

    def test_cookie_str2(self):
        c = self.jar.makeCookie(self.exp, self.data)
        s = SimpleCookie()
        s.load(c.output(header=""))
        self.assertTrue(self.jar.isGoodCookieString(s.output(header="")))

    def test_cookie_str_expired(self):
        t = self.exp - 7200
        c = self.jar.makeCookie(t, self.data)
        s = SimpleCookie()
        s.load(c.output(header=""))
        self.assertFalse(self.jar.isGoodCookieString(s.output(header="")))

    def test_cookie_str_arbitrary_change(self):
        c = self.jar.makeCookie(self.exp, self.data)
        cout = c.output(header="")
        cout_str = cout[:20] + "this is bad" + cout[20:]
        s = SimpleCookie()
        s.load(cout_str)
        self.assertFalse(self.jar.isGoodCookieString(s.output(header="")))

    def test_cookie_str_changed_exp(self):
        c = self.jar.makeCookie(self.exp, self.data)
        cout = c.output(header="")
        cout_str = self._corrupt_part_str(cout, 14, 16)
        s = SimpleCookie()
        s.load(cout_str)
        self.assertFalse(self.jar.isGoodCookieString(s.output(header="")))

    def test_cookie_str_changed_data(self):
        c = self.jar.makeCookie(self.exp, self.data)
        cout = c.output(header="")
        cout_str = self._corrupt_part_str(cout, 24, 26)
        s = SimpleCookie()
        s.load(cout_str)
        self.assertFalse(self.jar.isGoodCookieString(s.output(header="")))

    def test_cookie_str_changed_mac(self):
        c = self.jar.makeCookie(self.exp, self.data)
        cout = c.output(header="")
        cout_str = self._corrupt_part_str(cout, 64, 66)
        s = SimpleCookie()
        s.load(cout_str)
        self.assertFalse(self.jar.isGoodCookieString(s.output(header="")))

    def test_cookie_str_control_chars(self):
        """Cookie strings with control characters must be rejected.

        Python 3.13.12+ raises CookieError for control characters in
        cookie values (CVE-2026-0672).  isGoodCookieString() must
        return False instead of propagating the exception.
        """
        c = self.jar.makeCookie(self.exp, self.data)
        cout = c.output(header="")
        # Inject a DEL (0x7f) control character into the cookie value
        # to simulate the scenario that triggered CVE-2026-0672.
        cout_with_ctrl = cout[:40] + "\x7f" + cout[41:]
        self.assertFalse(self.jar.isGoodCookieString(cout_with_ctrl))
        # Also test with low control characters (e.g. BEL 0x07).
        cout_with_bel = cout[:40] + "\x07" + cout[41:]
        self.assertFalse(self.jar.isGoodCookieString(cout_with_bel))


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(AuthCookieTestCase)


if __name__ == "__main__":
    Rand.load_file("randpool.dat", -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file("randpool.dat")
