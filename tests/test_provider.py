#!/usr/bin/env python3
"""Test file for M2Crypto.Provider."""

import hashlib
import os
import shutil
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

        # Use mkdtemp + explicit cleanup for Python 3.6+ compatibility.
        cls.tempdir = tempfile.mkdtemp(prefix="m2crypto-provider-")
        openssl_conf = os.path.join(cls.tempdir, "openssl.conf")
        softhsm_conf = os.path.join(cls.tempdir, "softhsm2.conf")

        # M2Crypto loads providers by provider name (e.g. "pkcs11"), which in
        # many OpenSSL installations maps to a module file named "pkcs11.so".
        # Some platforms/package layouts ship the PKCS#11 provider module under
        # a different filename (e.g. "pkcs11prov.so"). Create a private module
        # directory for this test and provide both filenames.
        modules_dir = os.path.join(cls.tempdir, "ossl-modules")
        os.mkdir(modules_dir)
        local_pkcs11prov = os.path.join(modules_dir, "pkcs11prov.so")
        local_pkcs11 = os.path.join(modules_dir, "pkcs11.so")
        shutil.copy(openssl_module_pkcs11, local_pkcs11prov)
        shutil.copy(openssl_module_pkcs11, local_pkcs11)
        openssl_module_pkcs11 = local_pkcs11prov

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

        # Basic debugging info to make CI failures actionable.
        print("PKCS#11 integration test configuration:")
        print(f"  OPENSSL_CONF={openssl_conf}")
        print(f"  SOFTHSM2_CONF={softhsm_conf}")
        print(f"  M2CRYPTO_OPENSSL_MODULE_PKCS11={openssl_module_pkcs11}")
        print(f"  M2CRYPTO_PKCS11_MODULE_PATH={pkcs11_module_path}")
        try:
            with open(openssl_conf, "r") as f:
                print("  --- openssl.conf ---")
                print(f.read())
                print("  --- end openssl.conf ---")
        except OSError as e:
            print(f"  Could not read openssl.conf: {e}")
        try:
            with open(softhsm_conf, "r") as f:
                print("  --- softhsm2.conf ---")
                print(f.read())
                print("  --- end softhsm2.conf ---")
        except OSError as e:
            print(f"  Could not read softhsm2.conf: {e}")

        # Set environment variables, these must be set before loading the provider
        os.environ["OPENSSL_CONF"] = openssl_conf
        os.environ["SOFTHSM2_CONF"] = softhsm_conf
        # pkcs11prov (libp11) also supports configuration via environment.
        # Using env vars keeps the provider-openssl.conf template portable.
        os.environ.setdefault("PKCS11_MODULE_PATH", pkcs11_module_path)
        os.environ.setdefault("PKCS11_PIN", PIN)
        # Ensure OpenSSL can discover the provider module.
        os.environ["OPENSSL_MODULES"] = modules_dir

        # Verify which OpenSSL providers are active (helps debug pkcs11 URI loading).
        subprocess.run(["openssl", "list", "-providers"], check=True)

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

        # Show token contents after generating the key.
        subprocess.run(
            [
                "pkcs11-tool",
                "--module",
                pkcs11_module_path,
                "--login",
                "--pin",
                PIN,
                "--list-objects",
            ],
            check=True,
        )

        # Generate and import a certificate
        cert_der = os.path.join(cls.tempdir, "01_cert.der")
        # Generate a self-signed certificate using the PKCS#11 private key.
        # Capture output to provide useful diagnostics on failures.
        res = subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-days",
                "365",
                "-key",
                PRIVKEY_URI,
                "-subj",
                "/CN=01_cert/",
                "-out",
                cert_der,
                "-outform",
                "der",
            ],
            text=True,
            capture_output=True,
        )
        if res.returncode != 0:
            print("openssl req failed")
            print(f"  returncode={res.returncode}")
            if res.stdout:
                print("  --- stdout ---")
                print(res.stdout)
            if res.stderr:
                print("  --- stderr ---")
                print(res.stderr)
            res.check_returncode()

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

    @classmethod
    def tearDownClass(cls):
        # Best-effort cleanup; tests may create extra files under tempdir.
        if getattr(cls, "tempdir", None):
            shutil.rmtree(cls.tempdir, ignore_errors=True)

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
