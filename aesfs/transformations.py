"""
AES Transformation Operations Module

This module implements the four main AES transformations:
- SubBytes and InvSubBytes
- ShiftRows and InvShiftRows
- MixColumns and InvMixColumns
- AddRoundKey

High cohesion: Contains only transformation operations.
Low coupling: Depends only on constants and galois_field modules.
"""

from typing import List
from .constants import SBOX, INV_SBOX
from .galois_field import gmul_2, gmul_3, gmul_9, gmul_11, gmul_13, gmul_14


def sub_bytes(state: List[List[int]]) -> None:
    """
    Apply SubBytes transformation to the state.
    Substitutes each byte in the state with a corresponding value from the S-box.
    
    Args:
        state: 4x4 state matrix to transform (modified in place)
    """
    for i in range(4):
        for j in range(4):
            state[i][j] = SBOX[state[i][j]]


def inv_sub_bytes(state: List[List[int]]) -> None:
    """
    Apply inverse SubBytes transformation to the state.
    
    Args:
        state: 4x4 state matrix to transform (modified in place)
    """
    for i in range(4):
        for j in range(4):
            state[i][j] = INV_SBOX[state[i][j]]


def shift_rows(state: List[List[int]]) -> None:
    """
    Apply ShiftRows transformation to the state.
    Cyclically shifts the bytes in each row by different offsets.
    
    Args:
        state: 4x4 state matrix to transform (modified in place)
    """
    # Row 0: no shift
    # Row 1: shift left by 1
    state[1] = state[1][1:] + state[1][:1]
    # Row 2: shift left by 2
    state[2] = state[2][2:] + state[2][:2]
    # Row 3: shift left by 3
    state[3] = state[3][3:] + state[3][:3]


def inv_shift_rows(state: List[List[int]]) -> None:
    """
    Apply inverse ShiftRows transformation to the state.
    
    Args:
        state: 4x4 state matrix to transform (modified in place)
    """
    # Row 0: no shift
    # Row 1: shift right by 1
    state[1] = state[1][-1:] + state[1][:-1]
    # Row 2: shift right by 2
    state[2] = state[2][-2:] + state[2][:-2]
    # Row 3: shift right by 3
    state[3] = state[3][-3:] + state[3][:-3]


def mix_columns(state: List[List[int]]) -> None:
    """
    Apply MixColumns transformation to the state.
    Performs matrix multiplication in GF(2^8) for each column.
    
    Args:
        state: 4x4 state matrix to transform (modified in place)
    """
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        state[0][i] = gmul_2(col[0]) ^ gmul_3(col[1]) ^ col[2] ^ col[3]
        state[1][i] = col[0] ^ gmul_2(col[1]) ^ gmul_3(col[2]) ^ col[3]
        state[2][i] = col[0] ^ col[1] ^ gmul_2(col[2]) ^ gmul_3(col[3])
        state[3][i] = gmul_3(col[0]) ^ col[1] ^ col[2] ^ gmul_2(col[3])


def inv_mix_columns(state: List[List[int]]) -> None:
    """
    Apply inverse MixColumns transformation to the state.
    
    Args:
        state: 4x4 state matrix to transform (modified in place)
    """
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        state[0][i] = gmul_14(col[0]) ^ gmul_11(col[1]) ^ gmul_13(col[2]) ^ gmul_9(col[3])
        state[1][i] = gmul_9(col[0]) ^ gmul_14(col[1]) ^ gmul_11(col[2]) ^ gmul_13(col[3])
        state[2][i] = gmul_13(col[0]) ^ gmul_9(col[1]) ^ gmul_14(col[2]) ^ gmul_11(col[3])
        state[3][i] = gmul_11(col[0]) ^ gmul_13(col[1]) ^ gmul_9(col[2]) ^ gmul_14(col[3])


def add_round_key(state: List[List[int]], round_key: List[int]) -> None:
    """
    Apply AddRoundKey transformation to the state.
    XORs the state with the round key.
    
    Args:
        state: 4x4 state matrix to transform (modified in place)
        round_key: 16-byte round key
    """
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i + 4 * j]
