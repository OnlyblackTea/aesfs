"""Tests for Galois Field operations."""

import unittest
from aesfs.galois_field import gmul, gmul_2, gmul_3, gmul_9, gmul_11, gmul_13, gmul_14


class TestGaloisField(unittest.TestCase):
    """Test Galois Field operations."""
    
    def test_gmul_basic(self):
        """Test basic Galois Field multiplication."""
        # Test identity: x * 1 = x
        self.assertEqual(gmul(0x57, 0x01), 0x57)
        
        # Test zero: x * 0 = 0
        self.assertEqual(gmul(0x57, 0x00), 0x00)
        
        # Test known values
        self.assertEqual(gmul(0x57, 0x83), 0xC1)
        self.assertEqual(gmul(0x13, 0x0D), 0xC7)
    
    def test_gmul_2(self):
        """Test multiplication by 2 in GF(2^8)."""
        self.assertEqual(gmul_2(0x57), gmul(0x57, 0x02))
        self.assertEqual(gmul_2(0xAA), gmul(0xAA, 0x02))
        self.assertEqual(gmul_2(0x00), 0x00)
    
    def test_gmul_3(self):
        """Test multiplication by 3 in GF(2^8)."""
        self.assertEqual(gmul_3(0x57), gmul(0x57, 0x03))
        self.assertEqual(gmul_3(0xAA), gmul(0xAA, 0x03))
    
    def test_gmul_9(self):
        """Test multiplication by 9 in GF(2^8)."""
        self.assertEqual(gmul_9(0x57), gmul(0x57, 0x09))
    
    def test_gmul_11(self):
        """Test multiplication by 11 in GF(2^8)."""
        self.assertEqual(gmul_11(0x57), gmul(0x57, 0x0B))
    
    def test_gmul_13(self):
        """Test multiplication by 13 in GF(2^8)."""
        self.assertEqual(gmul_13(0x57), gmul(0x57, 0x0D))
    
    def test_gmul_14(self):
        """Test multiplication by 14 in GF(2^8)."""
        self.assertEqual(gmul_14(0x57), gmul(0x57, 0x0E))


if __name__ == '__main__':
    unittest.main()
