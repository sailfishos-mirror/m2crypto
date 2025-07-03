#!/usr/bin/env python3
"""Test file for M2Crypto.Provider."""

import hashlib
import os
import subprocess
import tempfile
import unittest
from M2Crypto import Provider

PIN = "123456"
SO_PIN = "12345678"

# Constants for PKCS#11 object identification
CERT_URI = "pkcs11:id=%01;type=cert"
PRIVKEY_URI = f"pkcs11:id=%01;type=private?pin-value={PIN}"
PUBKEY_URI = "pkcs11:id=%01;type=public"


class TestM2CryptoProvider(unittest.TestCase):
    """
    Test suite for M2Crypto.Provider using a PKCS#11 device.

    Note: This is an integration test and requires a properly configured
    PKCS#11 provider with a certificate and corresponding private/public
    keys available at id=%01.
    """

    @classmethod
    def getenv(cls, name):
        value = os.getenv(name)
        if value:
            return value
        else:
            raise unittest.SkipTest(f"Could not get environment variable {name}")

    @classmethod
    def writeOpensslConf(
        cls, openssl_conf, openssl_module_pkcs11, pkcs11_module_path, pin_file
    ):
        with open("tests/provider-openssl.conf", "r") as fin:
            openssl_conf_str = fin.read()
        openssl_conf_str = openssl_conf_str.replace(
            "@OPENSSL_MODULE_PKCS11@", openssl_module_pkcs11
        )
        openssl_conf_str = openssl_conf_str.replace(
            "@PKCS11_MODULE_PATH@", pkcs11_module_path
        )
        openssl_conf_str = openssl_conf_str.replace("@PIN_FILE@", pin_file)
        with open(openssl_conf, "w") as fout:
            fout.write(openssl_conf_str)

    @classmethod
    def writeSoftHsmCConf(cls, softhsm_conf, tokens_dir):
        with open("tests/provider-softhsm2.conf", "r") as fin:
            softhsm_conf_str = fin.read()
        softhsm_conf_str = softhsm_conf_str.replace("@TOKENS_DIR@", tokens_dir)
        with open(softhsm_conf, "w") as fout:
            fout.write(softhsm_conf_str)

    @classmethod
    def setUpClass(cls):
        """
        Initialize the PKCS#11 provider and load cryptographic objects.
        """

        openssl_module_pkcs11 = cls.getenv("M2CRYPTO_OPENSSL_MODULE_PKCS11")
        pkcs11_module_path = cls.getenv("M2CRYPTO_PKCS11_MODULE_PATH")

        cls.tempdir = tempfile.TemporaryDirectory(delete=False).name
        openssl_conf = os.path.join(cls.tempdir, "openssl.conf")
        softhsm_conf = os.path.join(cls.tempdir, "softhsm2.conf")

        # Create necessary file and folder
        pin_file = os.path.join(cls.tempdir, "pin.txt")
        with open(pin_file, "w") as f:
            f.write(f"{PIN}\n")
        tokens_dir = os.path.join(cls.tempdir, "tokens")
        os.mkdir(tokens_dir)

        # Write configuration files
        cls.writeOpensslConf(
            openssl_conf, openssl_module_pkcs11, pkcs11_module_path, pin_file
        )
        cls.writeSoftHsmCConf(softhsm_conf, tokens_dir)

        # Set environment variables, these must be set before loading the provider
        os.environ["OPENSSL_CONF"] = openssl_conf
        os.environ["SOFTHSM2_CONF"] = softhsm_conf

        # Init HSM
        subprocess.run(
            [
                "softhsm2-util",
                "--init-token",
                "--slot",
                "0",
                "--label",
                "SoftHSM2_Token",
                "--so-pin",
                SO_PIN,
                "--pin",
                PIN,
            ],
            check=True,
        )

        # Generate key pair
        subprocess.run(
            [
                "pkcs11-tool",
                "--module",
                pkcs11_module_path,
                "--login",
                "--pin",
                PIN,
                "--keypairgen",
                "--key-type",
                "RSA:2048",
                "--id",
                "1",
            ],
            check=True,
        )

        # Generate and import a certificate
        cert_der = os.path.join(cls.tempdir, "01_cert.der")
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-days",
                "365",
                "-key",
                "pkcs11:%01",
                "-subj",
                "/CN=01_cert/",
                "-out",
                cert_der,
                "-outform",
                "der",
            ],
            check=True,
        )

        subprocess.run(
            [
                "pkcs11-tool",
                "--module",
                pkcs11_module_path,
                "--login",
                "--pin",
                PIN,
                "--write-object",
                cert_der,
                "--type",
                "cert",
                "--id",
                "1",
            ],
            check=True,
        )

        try:
            cls.provider = Provider.Provider("pkcs11")
            cls.cert = cls.provider.load_certificate(CERT_URI)
            cls.privkey = cls.provider.load_key(PRIVKEY_URI)
            cls.pubkey = cls.provider.load_key(PUBKEY_URI)
        except Provider.ProviderError as e:
            # If the provider or keys can't be loaded, skip all tests in this class.
            raise unittest.SkipTest(
                f"Could not initialize PKCS#11 provider or load objects: {e}"
            )

    def test_public_key_der_comparison(self):
        """
        Ensures the public key from the certificate matches the loaded public key.
        """
        cert_pubkey = self.cert.get_pubkey()
        self.assertIsNotNone(
            cert_pubkey, "Failed to extract public key from certificate."
        )
        # Compare the full public keys in their DER format.
        self.assertEqual(
            cert_pubkey.as_der(),
            self.pubkey.as_der(),
            "Public key from certificate does not match the loaded public key.",
        )

    def test_public_key_modulus_comparison(self):
        """
        Ensures the modulus of the public key from the certificate matches
        the modulus of the loaded public key.
        """
        cert_pubkey = self.cert.get_pubkey()
        self.assertIsNotNone(
            cert_pubkey, "Failed to extract public key from certificate."
        )
        # Compare the modulus component of the public keys.
        self.assertEqual(
            cert_pubkey.get_modulus(),
            self.pubkey.get_modulus(),
            "Public key moduli do not match.",
        )

    def test_sign_and_verify(self):
        """
        Tests the complete sign-and-verify round-trip operation.
        """
        # 1. Create data to be signed
        random_data = os.urandom(32)
        hashed_data = hashlib.sha256(random_data).digest()

        # 2. Sign the hash with the private key
        self.privkey.sign_init()
        self.privkey.sign_update(hashed_data)
        signature = self.privkey.sign_final()
        self.assertIsNotNone(signature, "Signing operation returned None.")

        # 3. Verify the signature with the public key
        self.pubkey.verify_init()
        self.pubkey.verify_update(hashed_data)
        # The verify_final method returns 1 for a successful verification.
        verification_status = self.pubkey.verify_final(signature)
        self.assertEqual(verification_status, 1, "Signature verification failed.")


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestM2CryptoProvider))
    return suite


if __name__ == "__main__":
    unittest.main()
