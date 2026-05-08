#!/usr/bin/env python

"""
Unit tests for M2Crypto.util.

Copyright (c) 2024 Matěj Cepl. All rights reserved.
"""

import os
import platform
import sys
from unittest.mock import patch

from M2Crypto import m2, util, Rand
from tests import unittest


class UtilTestCase(unittest.TestCase):

    @patch("getpass.getpass", return_value="qwerty")
    def test_passphrase_callback_returns_bytes(self, mocked_getpass):
        self.assertEqual(util.passphrase_callback(False), b"qwerty")
        mocked_getpass.assert_called_once_with("Enter passphrase:")

    def test_time_t_bits(self):
        # Test m2.time_t_bits() returns valid values (32 or 64) and handles edge cases
        bit32 = m2.time_t_bits()
        self.assertIsInstance(bit32, int)
        self.assertIn(bit32, (32, 64))

        # Musl libc may return 64-bit time_t on 32-bit systems; skip comparison if musl
        if platform.libc_ver() != ('', ''):
            self.skipTest("Skipping musl-specific test for now")

        # Ensure m2.time_t_bits() aligns with Python's architecture (sys.maxsize)
        if sys.maxsize > 2**32:
            self.assertIn(bit32, (64, ))
        else:
            self.assertIn(bit32, (32, ))


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(UtilTestCase)


if __name__ == "__main__":
    Rand.load_file("randpool.dat", -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file("randpool.dat")
