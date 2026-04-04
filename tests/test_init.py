#!/usr/bin/env python

"""Unit tests for M2Crypto initialization."""
import M2Crypto
from tests import unittest


class InitTestCase(unittest.TestCase):

    def test_version_info(self):
        self.assertIsInstance(M2Crypto.version_info, tuple)


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(InitTestCase)


if __name__ == "__main__":
    from M2Crypto import Rand

    Rand.load_file("randpool.dat", -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file("randpool.dat")
