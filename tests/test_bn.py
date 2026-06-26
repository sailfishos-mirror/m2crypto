#!/usr/bin/env python

"""
Unit tests for M2Crypto.BN.

Copyright (c) 2005 Open Source Applications Foundation. All rights reserved.
"""

import re
import warnings

from M2Crypto import BN, Rand, m2
from tests import unittest

loops = 16


class BNTestCase(unittest.TestCase):

    def test_rand(self):
        # defaults
        for _ in range(loops):
            r8 = BN.rand(8)

        # top
        for _ in range(loops):
            r8 = BN.rand(8, top=0)
            assert r8 & 128
        for _ in range(loops):
            r8 = BN.rand(8, top=1)
            assert r8 & 192

        # bottom
        for _ in range(loops):
            r8 = BN.rand(8, bottom=1)
            self.assertEqual(r8 % 2, 1)

        # make sure we can get big numbers and work with them
        for _ in range(loops):
            r8 = BN.rand(8, top=0)
            r16 = BN.rand(16, top=0)
            r32 = BN.rand(32, top=0)
            r64 = BN.rand(64, top=0)
            r128 = BN.rand(128, top=0)
            r256 = BN.rand(256, top=0)
            r512 = BN.rand(512, top=0)
            assert r8 < r16 < r32 < r64 < r128 < r256 < r512 < (r512 + 1)

    def test_rand_range(self):
        # small range
        for _ in range(loops):
            r = BN.rand_range(1)
            self.assertEqual(r, 0)

        for _ in range(loops):
            r = BN.rand_range(4)
            assert 0 <= r < 4

        # large range
        r512 = BN.rand(512, top=0)
        for _ in range(loops):
            r = BN.rand_range(r512)
            assert 0 <= r < r512

    def test_randfname(self):
        m = re.compile("^[a-zA-Z0-9]{8}$")
        for _ in range(loops):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                r = BN.randfname(8)
            assert m.match(r)


class BNConvTestCase(unittest.TestCase):
    """Regression tests for m2.hex_to_bn / m2.dec_to_bn.

    These wrap OpenSSL's BN_hex2bn / BN_dec2bn, which require a
    NUL-terminated C string.  The Python wrappers must copy the
    incoming buffer into a NUL-terminated scratch area; passing the
    raw buffer pointer is an out-of-bounds read on hostile input.
    """

    def test_hex_to_bn_roundtrip(self):
        bn = m2.hex_to_bn(b"deadbeef")
        # bn_to_hex returns bytes (the .pyi annotation is incorrect)
        self.assertEqual(m2.bn_to_hex(bn).upper(), b"DEADBEEF")

    def test_dec_to_bn_roundtrip(self):
        bn_dec = m2.dec_to_bn(b"3735928559")  # 0xDEADBEEF
        bn_hex = m2.hex_to_bn(b"deadbeef")
        self.assertEqual(m2.bn_to_bin(bn_dec), m2.bn_to_bin(bn_hex))

    def test_hex_to_bn_non_nul_terminated(self):
        """The bytearray slice has no trailing NUL: must not OOB-read.

        Before the fix, BN_hex2bn would read past the end of the
        buffer until it found a NUL or a non-hex byte.  After the fix,
        the wrapper copies into its own NUL-terminated scratch buffer,
        so the result must depend only on the slice contents.
        """
        big = bytearray(b"deadbeef" + b"ZZZZZZZZ")
        view = memoryview(big)[:8]
        bn = m2.hex_to_bn(view)
        self.assertEqual(m2.bn_to_hex(bn).upper(), b"DEADBEEF")

    def test_dec_to_bn_non_nul_terminated(self):
        big = bytearray(b"12345" + b"9999")
        view = memoryview(big)[:5]
        bn = m2.dec_to_bn(view)
        self.assertEqual(int(m2.bn_to_hex(bn), 16), 12345)

    def test_hex_to_bn_rejects_str(self):
        # Note: the underlying TypeError is wrapped in SystemError by
        # SWIG's BIGNUM* output typemap (pre-existing behaviour).
        with self.assertRaises((TypeError, SystemError)):
            m2.hex_to_bn("deadbeef")

    def test_dec_to_bn_rejects_str(self):
        with self.assertRaises((TypeError, SystemError)):
            m2.dec_to_bn("12345")


def suite():
    t_suite = unittest.TestSuite()
    t_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(BNTestCase))
    t_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(BNConvTestCase))
    return t_suite


if __name__ == "__main__":
    Rand.load_file("randpool.dat", -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file("randpool.dat")
