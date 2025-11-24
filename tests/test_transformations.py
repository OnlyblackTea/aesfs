"""Tests for AES transformation operations."""

import unittest
from aesfs.transformations import (
    sub_bytes, inv_sub_bytes,
    shift_rows, inv_shift_rows,
    mix_columns, inv_mix_columns,
    add_round_key
)


class TestTransformations(unittest.TestCase):
    """Test AES transformation operations."""
    
    def test_sub_bytes_inv_sub_bytes(self):
        """Test SubBytes and InvSubBytes are inverses."""
        state = [
            [0x19, 0xa0, 0x9a, 0xe9],
            [0x3d, 0xf4, 0xc6, 0xf8],
            [0xe3, 0xe2, 0x8d, 0x48],
            [0xbe, 0x2b, 0x2a, 0x08]
        ]
        original = [row[:] for row in state]
        
        sub_bytes(state)
        inv_sub_bytes(state)
        
        self.assertEqual(state, original)
    
    def test_shift_rows_inv_shift_rows(self):
        """Test ShiftRows and InvShiftRows are inverses."""
        state = [
            [0x19, 0xa0, 0x9a, 0xe9],
            [0x3d, 0xf4, 0xc6, 0xf8],
            [0xe3, 0xe2, 0x8d, 0x48],
            [0xbe, 0x2b, 0x2a, 0x08]
        ]
        original = [row[:] for row in state]
        
        shift_rows(state)
        inv_shift_rows(state)
        
        self.assertEqual(state, original)
    
    def test_mix_columns_inv_mix_columns(self):
        """Test MixColumns and InvMixColumns are inverses."""
        state = [
            [0xdb, 0x13, 0x53, 0x45],
            [0xf2, 0x0a, 0x22, 0x5c],
            [0x01, 0x01, 0x01, 0x01],
            [0xc6, 0xc6, 0xc6, 0xc6]
        ]
        original = [row[:] for row in state]
        
        mix_columns(state)
        inv_mix_columns(state)
        
        self.assertEqual(state, original)
    
    def test_add_round_key_involutory(self):
        """Test AddRoundKey is its own inverse."""
        state = [
            [0x19, 0xa0, 0x9a, 0xe9],
            [0x3d, 0xf4, 0xc6, 0xf8],
            [0xe3, 0xe2, 0x8d, 0x48],
            [0xbe, 0x2b, 0x2a, 0x08]
        ]
        round_key = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
        ]
        original = [row[:] for row in state]
        
        add_round_key(state, round_key)
        add_round_key(state, round_key)
        
        self.assertEqual(state, original)
    
    def test_shift_rows_pattern(self):
        """Test ShiftRows shifts rows correctly."""
        state = [
            [0x01, 0x02, 0x03, 0x04],
            [0x05, 0x06, 0x07, 0x08],
            [0x09, 0x0A, 0x0B, 0x0C],
            [0x0D, 0x0E, 0x0F, 0x10]
        ]
        
        shift_rows(state)
        
        expected = [
            [0x01, 0x02, 0x03, 0x04],  # Row 0: no shift
            [0x06, 0x07, 0x08, 0x05],  # Row 1: shift left by 1
            [0x0B, 0x0C, 0x09, 0x0A],  # Row 2: shift left by 2
            [0x10, 0x0D, 0x0E, 0x0F]   # Row 3: shift left by 3
        ]
        
        self.assertEqual(state, expected)


if __name__ == '__main__':
    unittest.main()
