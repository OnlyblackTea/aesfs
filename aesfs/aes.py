"""
AES Cipher Module

This module implements the main AES cipher class for encryption and decryption.
High cohesion: Contains only the high-level encryption/decryption logic.
Low coupling: Orchestrates other modules without implementing low-level details.
"""

from typing import List
from .key_expansion import expand_key, get_round_key
from .transformations import (
    sub_bytes, inv_sub_bytes,
    shift_rows, inv_shift_rows,
    mix_columns, inv_mix_columns,
    add_round_key
)


class AES:
    """
    AES cipher implementation supporting 128, 192, and 256-bit keys.
    
    This class provides a high-level interface for AES encryption and decryption,
    orchestrating the various transformation and key expansion modules.
    """
    
    def __init__(self, key: bytes, key_size: int = 128):
        """
        Initialize the AES cipher with a key.
        
        Args:
            key: The encryption key (16, 24, or 32 bytes)
            key_size: Key size in bits (128, 192, or 256)
        
        Raises:
            ValueError: If key or key_size is invalid
        """
        if key_size not in (128, 192, 256):
            raise ValueError("Key size must be 128, 192, or 256 bits")
        
        if len(key) != key_size // 8:
            raise ValueError(f"Key must be {key_size // 8} bytes for {key_size}-bit AES")
        
        self.key_size = key_size
        self.nr = {128: 10, 192: 12, 256: 14}[key_size]
        self.expanded_key = expand_key(key, key_size)
    
    def _bytes_to_state(self, block: bytes) -> List[List[int]]:
        """
        Convert a 16-byte block to a 4x4 state matrix.
        
        Args:
            block: 16-byte input block
        
        Returns:
            4x4 state matrix
        """
        if len(block) != 16:
            raise ValueError("Block must be 16 bytes")
        
        state = [[0] * 4 for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[i][j] = block[i + 4 * j]
        return state
    
    def _state_to_bytes(self, state: List[List[int]]) -> bytes:
        """
        Convert a 4x4 state matrix to a 16-byte block.
        
        Args:
            state: 4x4 state matrix
        
        Returns:
            16-byte output block
        """
        block = []
        for j in range(4):
            for i in range(4):
                block.append(state[i][j])
        return bytes(block)
    
    def encrypt_block(self, plaintext: bytes) -> bytes:
        """
        Encrypt a single 16-byte block.
        
        Args:
            plaintext: 16-byte plaintext block
        
        Returns:
            16-byte ciphertext block
        
        Raises:
            ValueError: If plaintext is not 16 bytes
        """
        state = self._bytes_to_state(plaintext)
        
        # Initial round
        add_round_key(state, get_round_key(self.expanded_key, 0))
        
        # Main rounds
        for round_num in range(1, self.nr):
            sub_bytes(state)
            shift_rows(state)
            mix_columns(state)
            add_round_key(state, get_round_key(self.expanded_key, round_num))
        
        # Final round (no MixColumns)
        sub_bytes(state)
        shift_rows(state)
        add_round_key(state, get_round_key(self.expanded_key, self.nr))
        
        return self._state_to_bytes(state)
    
    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """
        Decrypt a single 16-byte block.
        
        Args:
            ciphertext: 16-byte ciphertext block
        
        Returns:
            16-byte plaintext block
        
        Raises:
            ValueError: If ciphertext is not 16 bytes
        """
        state = self._bytes_to_state(ciphertext)
        
        # Initial round
        add_round_key(state, get_round_key(self.expanded_key, self.nr))
        
        # Main rounds
        for round_num in range(self.nr - 1, 0, -1):
            inv_shift_rows(state)
            inv_sub_bytes(state)
            add_round_key(state, get_round_key(self.expanded_key, round_num))
            inv_mix_columns(state)
        
        # Final round (no InvMixColumns)
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, get_round_key(self.expanded_key, 0))
        
        return self._state_to_bytes(state)
    
    def encrypt(self, plaintext: bytes, padding: bool = True) -> bytes:
        """
        Encrypt data with optional PKCS7 padding.
        
        Args:
            plaintext: Data to encrypt
            padding: Whether to apply PKCS7 padding (default: True)
        
        Returns:
            Encrypted ciphertext
        """
        if padding:
            plaintext = self._pad(plaintext)
        elif len(plaintext) % 16 != 0:
            raise ValueError("Plaintext length must be multiple of 16 when padding is disabled")
        
        ciphertext = b''
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i + 16]
            ciphertext += self.encrypt_block(block)
        
        return ciphertext
    
    def decrypt(self, ciphertext: bytes, padding: bool = True) -> bytes:
        """
        Decrypt data with optional PKCS7 unpadding.
        
        Args:
            ciphertext: Data to decrypt
            padding: Whether to remove PKCS7 padding (default: True)
        
        Returns:
            Decrypted plaintext
        
        Raises:
            ValueError: If ciphertext length is not a multiple of 16
        """
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")
        
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            plaintext += self.decrypt_block(block)
        
        if padding:
            plaintext = self._unpad(plaintext)
        
        return plaintext
    
    def _pad(self, data: bytes) -> bytes:
        """
        Apply PKCS7 padding to data.
        
        Args:
            data: Data to pad
        
        Returns:
            Padded data
        """
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad(self, data: bytes) -> bytes:
        """
        Remove PKCS7 padding from data.
        
        Args:
            data: Padded data
        
        Returns:
            Unpadded data
        
        Raises:
            ValueError: If padding is invalid
        """
        if len(data) == 0:
            raise ValueError("Cannot unpad empty data")
        
        padding_length = data[-1]
        if padding_length > 16 or padding_length == 0:
            raise ValueError("Invalid padding")
        
        # Verify padding
        for i in range(padding_length):
            if data[-1 - i] != padding_length:
                raise ValueError("Invalid padding")
        
        return data[:-padding_length]
