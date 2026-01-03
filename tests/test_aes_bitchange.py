"""
Test AES encryption with bit changes in plaintext.

This module tests how small changes in plaintext (e.g., 2-bit change) affect
the intermediate states and final ciphertext during AES encryption.
It demonstrates the avalanche effect in AES encryption.
"""

import unittest
from typing import List, Dict, Tuple
from aesfs import AES
from aesfs.key_expansion import get_round_key
from aesfs.transformations import (
    sub_bytes, shift_rows, mix_columns, add_round_key
)


class AESWithIntermediateStates(AES):
    """
    Extended AES class that captures intermediate states during encryption.
    """
    
    def __init__(self, key: bytes, key_size: int = 128):
        """Initialize AES cipher with intermediate state tracking."""
        super().__init__(key, key_size, enable_logging=False)
        self.intermediate_states: Dict[str, List[List[int]]] = {}
    
    def _copy_state(self, state: List[List[int]]) -> List[List[int]]:
        """Create a deep copy of the state matrix."""
        return [row[:] for row in state]
    
    def encrypt_block_with_states(self, plaintext: bytes) -> Tuple[bytes, Dict[str, List[List[int]]]]:
        """
        Encrypt a block and capture all intermediate states.
        
        Args:
            plaintext: 16-byte plaintext block
        
        Returns:
            Tuple of (ciphertext, intermediate_states_dict)
        """
        self.intermediate_states = {}
        state = self._bytes_to_state(plaintext)
        
        # Store initial state
        self.intermediate_states['initial'] = self._copy_state(state)
        
        # Initial round - AddRoundKey
        add_round_key(state, get_round_key(self.expanded_key, 0))
        self.intermediate_states['round_0_add_round_key'] = self._copy_state(state)
        
        # Main rounds
        for round_num in range(1, self.nr):
            # SubBytes
            sub_bytes(state)
            self.intermediate_states[f'round_{round_num}_sub_bytes'] = self._copy_state(state)
            
            # ShiftRows
            shift_rows(state)
            self.intermediate_states[f'round_{round_num}_shift_rows'] = self._copy_state(state)
            
            # MixColumns
            mix_columns(state)
            self.intermediate_states[f'round_{round_num}_mix_columns'] = self._copy_state(state)
            
            # AddRoundKey
            add_round_key(state, get_round_key(self.expanded_key, round_num))
            self.intermediate_states[f'round_{round_num}_add_round_key'] = self._copy_state(state)
        
        # Final round (no MixColumns)
        # SubBytes
        sub_bytes(state)
        self.intermediate_states[f'round_{self.nr}_sub_bytes'] = self._copy_state(state)
        
        # ShiftRows
        shift_rows(state)
        self.intermediate_states[f'round_{self.nr}_shift_rows'] = self._copy_state(state)
        
        # AddRoundKey
        add_round_key(state, get_round_key(self.expanded_key, self.nr))
        self.intermediate_states[f'round_{self.nr}_add_round_key'] = self._copy_state(state)
        
        ciphertext = self._state_to_bytes(state)
        self.intermediate_states['final'] = self._copy_state(state)
        
        return ciphertext, self.intermediate_states


def state_to_hex_string(state: List[List[int]]) -> str:
    """
    Convert state matrix to a readable hex string.
    
    Args:
        state: 4x4 state matrix
    
    Returns:
        Hex string representation
    """
    result = []
    for j in range(4):
        for i in range(4):
            result.append(f"{state[i][j]:02X}")
    return " ".join(result)


def compare_states(state1: List[List[int]], state2: List[List[int]]) -> Tuple[int, List[Tuple[int, int, int, int]]]:
    """
    Compare two state matrices and return differences.
    
    Args:
        state1: First state matrix
        state2: Second state matrix
    
    Returns:
        Tuple of (number_of_differences, list_of_differences)
        Each difference is (row, col, value1, value2)
    """
    differences = []
    for i in range(4):
        for j in range(4):
            if state1[i][j] != state2[i][j]:
                differences.append((i, j, state1[i][j], state2[i][j]))
    
    return len(differences), differences


def print_state_comparison(stage_name: str, state1: List[List[int]], state2: List[List[int]]) -> None:
    """
    Print a comparison of two states at a specific stage.
    
    Args:
        stage_name: Name of the encryption stage
        state1: First state matrix
        state2: Second state matrix
    """
    num_diffs, differences = compare_states(state1, state2)
    
    print(f"\n{'=' * 80}")
    print(f"Stage: {stage_name}")
    print(f"{'=' * 80}")
    print(f"Plaintext 1 state: {state_to_hex_string(state1)}")
    print(f"Plaintext 2 state: {state_to_hex_string(state2)}")
    print(f"Differences: {num_diffs} bytes differ")
    
    if differences:
        print("\nDetailed differences:")
        for row, col, val1, val2 in differences:
            # Convert 2D state matrix position to linear byte position in column-major order
            position = row + 4 * col
            print(f"  Position [{row}][{col}] (byte {position:2d}): 0x{val1:02X} -> 0x{val2:02X} (XOR: 0x{val1 ^ val2:02X})")


class TestAESBitChange(unittest.TestCase):
    """Test AES encryption behavior with small bit changes in plaintext."""
    
    def test_two_bit_change_comparison(self):
        """
        Test encryption of two plaintexts differing by 2 bits.
        
        This test demonstrates the avalanche effect in AES encryption.
        Example: 0xFF FF FF FF vs 0xFF FF FC FF (2-bit difference in byte 2)
        """
        print("\n" + "=" * 80)
        print("AES Bit Change Test: Comparing Encryption of Two Similar Plaintexts")
        print("=" * 80)
        
        # Define test key (128-bit)
        key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
        
        # Define two plaintexts: second differs by 2 bits in the 3rd byte
        # 0xFF -> 0xFC: binary 11111111 -> 11111100 (2-bit difference)
        plaintext1 = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        plaintext2 = bytes([0xFF, 0xFF, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        
        print(f"\nKey:        {key.hex().upper()}")
        print(f"Plaintext 1: {plaintext1.hex().upper()}")
        print(f"Plaintext 2: {plaintext2.hex().upper()}")
        
        # Calculate bit difference
        bit_diff = bin(plaintext1[2] ^ plaintext2[2]).count('1')
        print(f"\nBit difference: {bit_diff} bits (byte 2: 0x{plaintext1[2]:02X} ^ 0x{plaintext2[2]:02X} = 0x{plaintext1[2] ^ plaintext2[2]:02X})")
        
        # Encrypt both plaintexts with intermediate state tracking
        cipher1 = AESWithIntermediateStates(key, 128)
        ciphertext1, states1 = cipher1.encrypt_block_with_states(plaintext1)
        
        cipher2 = AESWithIntermediateStates(key, 128)
        ciphertext2, states2 = cipher2.encrypt_block_with_states(plaintext2)
        
        # Print final results first
        print(f"\n{'=' * 80}")
        print("FINAL ENCRYPTION RESULTS")
        print(f"{'=' * 80}")
        print(f"Ciphertext 1: {ciphertext1.hex().upper()}")
        print(f"Ciphertext 2: {ciphertext2.hex().upper()}")
        
        # Calculate how many bytes differ in final ciphertext
        final_diffs = sum(1 for i in range(16) if ciphertext1[i] != ciphertext2[i])
        print(f"\nFinal ciphertext differences: {final_diffs}/16 bytes differ")
        print("This demonstrates the avalanche effect - a small change in input")
        print("causes significant changes in output!")
        
        # Compare intermediate states at each stage
        print(f"\n{'=' * 80}")
        print("INTERMEDIATE STATES COMPARISON")
        print(f"{'=' * 80}")
        
        # Compare all stages
        all_stages = sorted(states1.keys())
        
        for stage in all_stages:
            if stage in states1 and stage in states2:
                print_state_comparison(stage, states1[stage], states2[stage])
        
        # Verify that encryption works correctly
        # Decrypt to verify correctness
        standard_cipher = AES(key, 128)
        decrypted1 = standard_cipher.decrypt_block(ciphertext1)
        decrypted2 = standard_cipher.decrypt_block(ciphertext2)
        
        self.assertEqual(decrypted1, plaintext1, "Decryption should return original plaintext 1")
        self.assertEqual(decrypted2, plaintext2, "Decryption should return original plaintext 2")
        
        # Verify avalanche effect - final ciphertexts should be very different
        self.assertGreater(final_diffs, 8, "Avalanche effect: at least half of bytes should differ")
    
    def test_single_bit_change(self):
        """Test encryption with single bit change."""
        print("\n" + "=" * 80)
        print("AES Single Bit Change Test")
        print("=" * 80)
        
        key = bytes([0x00] * 16)
        
        # Single bit difference in first byte
        plaintext1 = bytes([0x00] * 16)
        plaintext2 = bytes([0x01] + [0x00] * 15)
        
        print(f"\nKey:        {key.hex().upper()}")
        print(f"Plaintext 1: {plaintext1.hex().upper()}")
        print(f"Plaintext 2: {plaintext2.hex().upper()}")
        print(f"Bit difference: 1 bit (byte 0: 0x{plaintext1[0]:02X} ^ 0x{plaintext2[0]:02X} = 0x{plaintext1[0] ^ plaintext2[0]:02X})")
        
        cipher1 = AESWithIntermediateStates(key, 128)
        ciphertext1, states1 = cipher1.encrypt_block_with_states(plaintext1)
        
        cipher2 = AESWithIntermediateStates(key, 128)
        ciphertext2, states2 = cipher2.encrypt_block_with_states(plaintext2)
        
        print(f"\nCiphertext 1: {ciphertext1.hex().upper()}")
        print(f"Ciphertext 2: {ciphertext2.hex().upper()}")
        
        final_diffs = sum(1 for i in range(16) if ciphertext1[i] != ciphertext2[i])
        print(f"\nFinal ciphertext differences: {final_diffs}/16 bytes differ")
        
        # Compare key stages
        key_stages = ['initial', 'round_1_add_round_key', 'round_5_add_round_key', 'final']
        for stage in key_stages:
            if stage in states1 and stage in states2:
                print_state_comparison(stage, states1[stage], states2[stage])
        
        # Verify avalanche effect
        self.assertGreater(final_diffs, 6, "Single bit change should affect multiple bytes")
    
    def test_multiple_bit_changes(self):
        """Test encryption with multiple byte changes."""
        print("\n" + "=" * 80)
        print("AES Multiple Bit Change Test")
        print("=" * 80)
        
        key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
        
        # Single bit different in byte 1: 0xAA vs 0xAB
        plaintext1 = bytes([0xAA] * 16)
        plaintext2 = bytes([0xAA, 0xAB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                           0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA])
        
        print(f"\nKey:        {key.hex().upper()}")
        print(f"Plaintext 1: {plaintext1.hex().upper()}")
        print(f"Plaintext 2: {plaintext2.hex().upper()}")
        print(f"Bit difference: 1 bit (byte 1: 0x{plaintext1[1]:02X} ^ 0x{plaintext2[1]:02X} = 0x{plaintext1[1] ^ plaintext2[1]:02X})")
        
        cipher1 = AESWithIntermediateStates(key, 128)
        ciphertext1, _ = cipher1.encrypt_block_with_states(plaintext1)
        
        cipher2 = AESWithIntermediateStates(key, 128)
        ciphertext2, _ = cipher2.encrypt_block_with_states(plaintext2)
        
        print(f"\nCiphertext 1: {ciphertext1.hex().upper()}")
        print(f"Ciphertext 2: {ciphertext2.hex().upper()}")
        
        final_diffs = sum(1 for i in range(16) if ciphertext1[i] != ciphertext2[i])
        print(f"\nFinal ciphertext differences: {final_diffs}/16 bytes differ")
        
        self.assertNotEqual(ciphertext1, ciphertext2, "Ciphertexts should differ")


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
