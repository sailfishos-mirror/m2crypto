import unittest
from M2Crypto import EVP


class TestAESGCM(unittest.TestCase):
    def test_encrypt_decrypt(self):
        key = b"this is a 16 byte key"[:16]
        iv = b"12 byte iv!!"
        plaintext = b"Hello, AES-GCM!"
        aad = b"Additional Data"

        # Encryption
        cipher = EVP.Cipher("aes_128_gcm", key, iv, 1)  # 1 = encrypt
        cipher.update_aad(aad)
        ciphertext = cipher.update(plaintext)
        cipher.final()
        tag = cipher.get_tag()

        # Decryption
        cipher_dec = EVP.Cipher("aes_128_gcm", key, iv, 0)  # 0 = decrypt
        cipher_dec.set_tag(tag)
        cipher_dec.update_aad(aad)
        decrypted = cipher_dec.update(ciphertext)
        res = cipher_dec.final()
        decrypted += res

        self.assertEqual(plaintext, decrypted)

    def test_wrong_tag(self):
        key = b"this is a 16 byte key"[:16]
        iv = b"12 byte iv!!"
        plaintext = b"Hello, AES-GCM!"
        cipher = EVP.Cipher("aes_128_gcm", key, iv, 1)
        ciphertext = cipher.update(plaintext)
        cipher.final()
        tag = cipher.get_tag()
        # Corrupt tag
        wrong_tag = bytearray(tag)
        wrong_tag[0] ^= 0xFF
        cipher_dec = EVP.Cipher("aes_128_gcm", key, iv, 0)
        cipher_dec.set_tag(bytes(wrong_tag))
        with self.assertRaises(Exception):
            cipher_dec.update(ciphertext)
            cipher_dec.final()

    def test_wrong_aad(self):
        key = b"this is a 16 byte key"[:16]
        iv = b"12 byte iv!!"
        plaintext = b"Hello, AES-GCM!"
        aad = b"Correct AAD"
        cipher = EVP.Cipher("aes_128_gcm", key, iv, 1)
        cipher.update_aad(aad)
        ciphertext = cipher.update(plaintext)
        cipher.final()
        tag = cipher.get_tag()
        cipher_dec = EVP.Cipher("aes_128_gcm", key, iv, 0)
        cipher_dec.set_tag(tag)
        cipher_dec.update_aad(b"Wrong AAD")
        with self.assertRaises(Exception):
            cipher_dec.update(ciphertext)
            cipher_dec.final()


if __name__ == "__main__":
    unittest.main()
