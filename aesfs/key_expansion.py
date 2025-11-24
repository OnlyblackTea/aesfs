"""
AES Key Expansion Module

This module handles the expansion of the cipher key into round keys.
High cohesion: Contains only key expansion logic.
Low coupling: Depends only on constants module.
"""

from typing import List
from .constants import SBOX, RCON


def rot_word(word: List[int]) -> List[int]:
    """
    Rotate a 4-byte word to the left.
    
    Args:
        word: 4-byte list
    
    Returns:
        Rotated word
    """
    return word[1:] + word[:1]


def sub_word(word: List[int]) -> List[int]:
    """
    Apply S-box substitution to each byte in a 4-byte word.
    
    Args:
        word: 4-byte list
    
    Returns:
        Substituted word
    """
    return [SBOX[b] for b in word]


def expand_key(key: bytes, key_size: int = 128) -> List[int]:
    """
    Expand the cipher key into round keys.
    
    Args:
        key: The cipher key (16, 24, or 32 bytes)
        key_size: Key size in bits (128, 192, or 256)
    
    Returns:
        Expanded key as a list of bytes
    
    Raises:
        ValueError: If key size is invalid
    """
    if key_size not in (128, 192, 256):
        raise ValueError("Key size must be 128, 192, or 256 bits")
    
    key_bytes = len(key)
    if key_bytes != key_size // 8:
        raise ValueError(f"Key must be {key_size // 8} bytes for {key_size}-bit AES")
    
    # Number of 32-bit words in the key
    nk = key_bytes // 4
    
    # Number of rounds
    if key_size == 128:
        nr = 10
    elif key_size == 192:
        nr = 12
    else:  # 256
        nr = 14
    
    # Total number of 32-bit words needed
    total_words = 4 * (nr + 1)
    
    # Initialize with the cipher key
    expanded_key = list(key)
    
    # Expand the key
    for i in range(nk, total_words):
        # Get the previous word
        temp = expanded_key[(i - 1) * 4: i * 4]
        
        if i % nk == 0:
            # Apply RotWord, SubWord, and XOR with Rcon
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            # Additional SubWord for 256-bit keys
            temp = sub_word(temp)
        
        # XOR with word nk positions earlier
        prev_word = expanded_key[(i - nk) * 4: (i - nk + 1) * 4]
        new_word = [prev_word[j] ^ temp[j] for j in range(4)]
        expanded_key.extend(new_word)
    
    return expanded_key


def get_round_key(expanded_key: List[int], round_num: int) -> List[int]:
    """
    Extract a specific round key from the expanded key.
    
    Args:
        expanded_key: The expanded key
        round_num: Round number (0 to nr)
    
    Returns:
        16-byte round key
    """
    start = round_num * 16
    return expanded_key[start:start + 16]
