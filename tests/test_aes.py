"""Tests for AES cipher."""

import unittest
from aesfs import AES


class TestAES(unittest.TestCase):
    """Test AES cipher."""
    
    def test_aes_128_encrypt_decrypt(self):
        """Test AES-128 encryption and decryption."""
        key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
        plaintext = b'Hello, AES World'
        
        cipher = AES(key, 128)
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_aes_128_block_encrypt_decrypt(self):
        """Test AES-128 single block encryption and decryption."""
        key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
        plaintext = bytes([0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                          0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34])
        
        cipher = AES(key, 128)
        ciphertext = cipher.encrypt_block(plaintext)
        decrypted = cipher.decrypt_block(ciphertext)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_aes_192_encrypt_decrypt(self):
        """Test AES-192 encryption and decryption."""
        key = bytes([0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                     0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                     0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b])
        plaintext = b'AES-192 Test Data'
        
        cipher = AES(key, 192)
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_aes_256_encrypt_decrypt(self):
        """Test AES-256 encryption and decryption."""
        key = bytes([0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                     0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                     0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                     0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4])
        plaintext = b'AES-256 is the strongest!'
        
        cipher = AES(key, 256)
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_padding(self):
        """Test PKCS7 padding and unpadding."""
        key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
        
        cipher = AES(key, 128)
        
        # Test various lengths
        for length in [1, 15, 16, 17, 31, 32]:
            plaintext = b'A' * length
            ciphertext = cipher.encrypt(plaintext)
            decrypted = cipher.decrypt(ciphertext)
            self.assertEqual(decrypted, plaintext)
    
    def test_no_padding(self):
        """Test encryption without padding."""
        key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
        plaintext = b'Exactly16BytesXX'  # Exactly 16 bytes
        
        cipher = AES(key, 128)
        ciphertext = cipher.encrypt(plaintext, padding=False)
        decrypted = cipher.decrypt(ciphertext, padding=False)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_long_message(self):
        """Test encryption of a longer message."""
        key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
        plaintext = b'This is a longer message that spans multiple blocks and tests the AES implementation thoroughly.'
        
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
        key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
        cipher = AES(key, 128)
        
        with self.assertRaises(ValueError):
            cipher.encrypt_block(b'Too short')
        
        with self.assertRaises(ValueError):
            cipher.encrypt(b'Not 16 bytes', padding=False)


if __name__ == '__main__':
    unittest.main()
