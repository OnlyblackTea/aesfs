"""
Galois Field (GF(2^8)) Operations Module

This module provides operations in the Galois Field GF(2^8) used by AES.
High cohesion: Contains only Galois Field mathematical operations.
Low coupling: No dependencies on other modules.
"""


def gmul(a: int, b: int) -> int:
    """
    Multiply two numbers in GF(2^8) using the AES irreducible polynomial.

    The multiplication is performed in the Galois Field with the
    irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).

    Args:
        a: First operand (0-255)
        b: Second operand (0-255)

    Returns:
        Product in GF(2^8) (0-255)
    """
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1B  # AES irreducible polynomial
        b >>= 1
    return p & 0xFF


def gmul_2(x: int) -> int:
    """
    Multiply by 2 in GF(2^8). Optimized version of gmul(x, 2).

    Args:
        x: Value to multiply (0-255)

    Returns:
        x * 2 in GF(2^8)
    """
    return ((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF


def gmul_3(x: int) -> int:
    """
    Multiply by 3 in GF(2^8). Optimized version of gmul(x, 3).

    Args:
        x: Value to multiply (0-255)

    Returns:
        x * 3 in GF(2^8)
    """
    return gmul_2(x) ^ x


def gmul_9(x: int) -> int:
    """
    Multiply by 9 in GF(2^8). Used in inverse MixColumns.

    Args:
        x: Value to multiply (0-255)

    Returns:
        x * 9 in GF(2^8)
    """
    return gmul(x, 9)


def gmul_11(x: int) -> int:
    """
    Multiply by 11 in GF(2^8). Used in inverse MixColumns.

    Args:
        x: Value to multiply (0-255)

    Returns:
        x * 11 in GF(2^8)
    """
    return gmul(x, 11)


def gmul_13(x: int) -> int:
    """
    Multiply by 13 in GF(2^8). Used in inverse MixColumns.

    Args:
        x: Value to multiply (0-255)

    Returns:
        x * 13 in GF(2^8)
    """
    return gmul(x, 13)


def gmul_14(x: int) -> int:
    """
    Multiply by 14 in GF(2^8). Used in inverse MixColumns.

    Args:
        x: Value to multiply (0-255)

    Returns:
        x * 14 in GF(2^8)
    """
    return gmul(x, 14)
