#!/usr/bin/env python

"""Unit tests for M2Crypto.RC4.

Copyright (c) 2009 Heikki Toivonen. All rights reserved."""

import warnings

from M2Crypto import RC4, Rand
from binascii import hexlify

from tests import unittest
from tests.fips import fips_mode


class RC4TestCase(unittest.TestCase):

    @unittest.skipIf(fips_mode, "Can't be run in FIPS mode")
    def test_vectors(self):
        """
        Test with test vectors from Wikipedia: http://en.wikipedia.org/wiki/Rc4
        """
        if fips_mode:
            return
        vectors = (
            (b"Key", b"Plaintext", b"BBF316E8D940AF0AD3"),
            (b"Wiki", b"pedia", b"1021BF0420"),
            (
                b"Secret",
                b"Attack at dawn",
                b"45A01F645FC35B383552544B9BF5",
            ),
        )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            rc4 = RC4.RC4()
            for key, plaintext, ciphertext in vectors:
                rc4.set_key(key)
                self.assertEqual(hexlify(rc4.update(plaintext)).upper(), ciphertext)

            self.assertEqual(rc4.final(), "")

    @unittest.skipIf(fips_mode, "Can't be run in FIPS mode")
    def test_bad(self):
        if fips_mode:
            return
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            rc4 = RC4.RC4(b"foo")
        self.assertNotEqual(hexlify(rc4.update(b"bar")).upper(), b"45678")

    @unittest.skipIf(fips_mode, "Can't be run in FIPS mode")
    def test_deprecation_warning(self):
        """RC4() must emit DeprecationWarning per RFC 7465."""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", DeprecationWarning)
            RC4.RC4(b"key")
        deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        self.assertEqual(len(deprecations), 1)
        self.assertIn("RC4", str(deprecations[0].message))


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(RC4TestCase)


if __name__ == "__main__":
    Rand.load_file("randpool.dat", -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file("randpool.dat")
