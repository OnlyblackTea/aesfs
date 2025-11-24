"""
AESFS - A simple AES implementation with high cohesion and low coupling.

This package provides a modular implementation of the AES encryption algorithm,
designed with separation of concerns and minimal dependencies between components.
"""

from .aes import AES

__version__ = "0.1.0"
__all__ = ["AES"]
