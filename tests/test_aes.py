"""Tests for AES cipher."""

import unittest
from aesfs import AES


class TestAES(unittest.TestCase):
    """Test AES cipher."""

    def test_aes_128_encrypt_decrypt(self):
        """Test AES-128 encryption and decryption."""
        key = bytes(
            [
                0x2B,
                0x7E,
                0x15,
                0x16,
                0x28,
                0xAE,
                0xD2,
                0xA6,
                0xAB,
                0xF7,
                0x15,
                0x88,
                0x09,
                0xCF,
                0x4F,
                0x3C,
            ]
        )
        plaintext = b"Hello, AES World"

        cipher = AES(key, 128)
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)

        self.assertEqual(decrypted, plaintext)

    def test_aes_128_block_encrypt_decrypt(self):
        """Test AES-128 single block encryption and decryption."""
        key = bytes(
            [
                0x2B,
                0x7E,
                0x15,
                0x16,
                0x28,
                0xAE,
                0xD2,
                0xA6,
                0xAB,
                0xF7,
                0x15,
                0x88,
                0x09,
                0xCF,
                0x4F,
                0x3C,
            ]
        )
        plaintext = bytes(
            [
                0x32,
                0x43,
                0xF6,
                0xA8,
                0x88,
                0x5A,
                0x30,
                0x8D,
                0x31,
                0x31,
                0x98,
                0xA2,
                0xE0,
                0x37,
                0x07,
                0x34,
            ]
        )

        cipher = AES(key, 128)
        ciphertext = cipher.encrypt_block(plaintext)
        decrypted = cipher.decrypt_block(ciphertext)

        self.assertEqual(decrypted, plaintext)

    def test_aes_192_encrypt_decrypt(self):
        """Test AES-192 encryption and decryption."""
        key = bytes(
            [
                0x8E,
                0x73,
                0xB0,
                0xF7,
                0xDA,
                0x0E,
                0x64,
                0x52,
                0xC8,
                0x10,
                0xF3,
                0x2B,
                0x80,
                0x90,
                0x79,
                0xE5,
                0x62,
                0xF8,
                0xEA,
                0xD2,
                0x52,
                0x2C,
                0x6B,
                0x7B,
            ]
        )
        plaintext = b"AES-192 Test Data"

        cipher = AES(key, 192)
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)

        self.assertEqual(decrypted, plaintext)

    def test_aes_256_encrypt_decrypt(self):
        """Test AES-256 encryption and decryption."""
        key = bytes(
            [
                0x60,
                0x3D,
                0xEB,
                0x10,
                0x15,
                0xCA,
                0x71,
                0xBE,
                0x2B,
                0x73,
                0xAE,
                0xF0,
                0x85,
                0x7D,
                0x77,
                0x81,
                0x1F,
                0x35,
                0x2C,
                0x07,
                0x3B,
                0x61,
                0x08,
                0xD7,
                0x2D,
                0x98,
                0x10,
                0xA3,
                0x09,
                0x14,
                0xDF,
                0xF4,
            ]
        )
        plaintext = b"AES-256 is the strongest!"

        cipher = AES(key, 256)
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)

        self.assertEqual(decrypted, plaintext)

    def test_padding(self):
        """Test PKCS7 padding and unpadding."""
        key = bytes(
            [
                0x2B,
                0x7E,
                0x15,
                0x16,
                0x28,
                0xAE,
                0xD2,
                0xA6,
                0xAB,
                0xF7,
                0x15,
                0x88,
                0x09,
                0xCF,
                0x4F,
                0x3C,
            ]
        )

        cipher = AES(key, 128)

        # Test various lengths
        for length in [1, 15, 16, 17, 31, 32]:
            plaintext = b"A" * length
            ciphertext = cipher.encrypt(plaintext)
            decrypted = cipher.decrypt(ciphertext)
            self.assertEqual(decrypted, plaintext)

    def test_no_padding(self):
        """Test encryption without padding."""
        key = bytes(
            [
                0x2B,
                0x7E,
                0x15,
                0x16,
                0x28,
                0xAE,
                0xD2,
                0xA6,
                0xAB,
                0xF7,
                0x15,
                0x88,
                0x09,
                0xCF,
                0x4F,
                0x3C,
            ]
        )
        plaintext = b"Exactly16BytesXX"  # Exactly 16 bytes

        cipher = AES(key, 128)
        ciphertext = cipher.encrypt(plaintext, padding=False)
        decrypted = cipher.decrypt(ciphertext, padding=False)

        self.assertEqual(decrypted, plaintext)

    def test_long_message(self):
        """Test encryption of a longer message."""
        key = bytes(
            [
                0x2B,
                0x7E,
                0x15,
                0x16,
                0x28,
                0xAE,
                0xD2,
                0xA6,
                0xAB,
                0xF7,
                0x15,
                0x88,
                0x09,
                0xCF,
                0x4F,
                0x3C,
            ]
        )
        plaintext = b"This is a longer message that spans multiple blocks and tests the AES implementation thoroughly."

        cipher = AES(key, 128)
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)

        self.assertEqual(decrypted, plaintext)

    def test_invalid_key_size(self):
        """Test error handling for invalid key sizes."""
        with self.assertRaises(ValueError):
            AES(bytes([0x00] * 16), 192)

        with self.assertRaises(ValueError):
            AES(bytes([0x00] * 10), 128)

    def test_invalid_block_size(self):
        """Test error handling for invalid block sizes."""
        key = bytes(
            [
                0x2B,
                0x7E,
                0x15,
                0x16,
                0x28,
                0xAE,
                0xD2,
                0xA6,
                0xAB,
                0xF7,
                0x15,
                0x88,
                0x09,
                0xCF,
                0x4F,
                0x3C,
            ]
        )
        cipher = AES(key, 128)

        with self.assertRaises(ValueError):
            cipher.encrypt_block(b"Too short")

        with self.assertRaises(ValueError):
            cipher.encrypt(b"Not 16 bytes", padding=False)


if __name__ == "__main__":
    unittest.main()
