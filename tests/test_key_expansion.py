"""Tests for AES key expansion."""

import unittest
from aesfs.key_expansion import expand_key, get_round_key, rot_word, sub_word


class TestKeyExpansion(unittest.TestCase):
    """Test AES key expansion."""

    def test_rot_word(self):
        """Test word rotation."""
        word = [0x01, 0x02, 0x03, 0x04]
        rotated = rot_word(word)
        self.assertEqual(rotated, [0x02, 0x03, 0x04, 0x01])

    def test_sub_word(self):
        """Test S-box substitution on word."""
        word = [0x00, 0x01, 0x02, 0x03]
        subbed = sub_word(word)
        self.assertEqual(subbed, [0x63, 0x7C, 0x77, 0x7B])

    def test_expand_key_128(self):
        """Test 128-bit key expansion."""
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

        expanded = expand_key(key, 128)

        # Should have 11 round keys (10 rounds + 1 initial)
        self.assertEqual(len(expanded), 176)  # 11 * 16 bytes

        # First 16 bytes should be the original key
        self.assertEqual(expanded[:16], list(key))

    def test_expand_key_192(self):
        """Test 192-bit key expansion."""
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

        expanded = expand_key(key, 192)

        # Should have 13 round keys (12 rounds + 1 initial)
        self.assertEqual(len(expanded), 208)  # 13 * 16 bytes

    def test_expand_key_256(self):
        """Test 256-bit key expansion."""
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

        expanded = expand_key(key, 256)

        # Should have 15 round keys (14 rounds + 1 initial)
        self.assertEqual(len(expanded), 240)  # 15 * 16 bytes

    def test_get_round_key(self):
        """Test extracting round keys."""
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

        expanded = expand_key(key, 128)

        # First round key should be the original key
        round_key_0 = get_round_key(expanded, 0)
        self.assertEqual(round_key_0, list(key))

        # Each round key should be 16 bytes
        for i in range(11):
            rk = get_round_key(expanded, i)
            self.assertEqual(len(rk), 16)

    def test_invalid_key_size(self):
        """Test error handling for invalid key sizes."""
        key = bytes([0x00] * 16)

        with self.assertRaises(ValueError):
            expand_key(key, 192)  # Wrong key size for 192-bit

        with self.assertRaises(ValueError):
            expand_key(key, 100)  # Invalid key size


if __name__ == "__main__":
    unittest.main()
