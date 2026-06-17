import unittest
from M2Crypto import EVP


class TestAESGCMSimple(unittest.TestCase):
    def test_encrypt_decrypt_no_aad(self):
        key = b"this is a 16 byte key"[:16]
        iv = b"12 byte iv!!"
        plaintext = b"Hello, AES-GCM!"

        # Encryption
        cipher = EVP.Cipher("aes_128_gcm", key, iv, 1)
        ciphertext = cipher.update(plaintext)
        cipher.final()
        tag = cipher.get_tag()

        # Decryption
        cipher_dec = EVP.Cipher("aes_128_gcm", key, iv, 0)
        cipher_dec.set_tag(tag)
        decrypted = cipher_dec.update(ciphertext)
        res = cipher_dec.final()
        decrypted += res

        self.assertEqual(plaintext, decrypted)


if __name__ == "__main__":
    unittest.main()
