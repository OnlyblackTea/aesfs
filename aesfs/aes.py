"""
AES Cipher Module

This module implements the main AES cipher class for encryption and decryption.
High cohesion: Contains only the high-level encryption/decryption logic.
Low coupling: Orchestrates other modules without implementing low-level details.
"""

import logging
from typing import List, Optional, Union
from .key_expansion import expand_key, get_round_key
from .transformations import (
    sub_bytes,
    inv_sub_bytes,
    shift_rows,
    inv_shift_rows,
    mix_columns,
    inv_mix_columns,
    add_round_key,
)
from .logger import get_logger
from .config import AESConfig, load_config


class AES:
    """
    AES cipher implementation supporting 128, 192, and 256-bit keys.

    This class provides a high-level interface for AES encryption and decryption,
    orchestrating the various transformation and key expansion modules.
    """

    def __init__(
        self,
        key: bytes,
        key_size: Optional[int] = None,
        enable_logging: Optional[bool] = None,
        config: Optional[Union[AESConfig, dict, str]] = None,
    ):
        """
        Initialize the AES cipher with a key.

        Args:
            key: The encryption key (16, 24, or 32 bytes)
            key_size: Key size in bits (128, 192, or 256). If None, uses config.
            enable_logging: Enable logging for operations. If None, uses config.
            config: Configuration source (AESConfig, dict, file path, or None).
                   If provided, config values are used as defaults.

        Raises:
            ValueError: If key or key_size is invalid

        Examples:
            # Traditional usage (backward compatible)
            cipher = AES(key, key_size=128, enable_logging=True)

            # With configuration file
            cipher = AES(key, config='config.yaml')

            # With configuration dict
            cipher = AES(key, config={'key_size': 256, 'padding': True})

            # Override config with explicit parameters
            cipher = AES(key, key_size=192, config='config.yaml')
        """
        self.logger = get_logger()

        # Load configuration
        if config is not None:
            self.config = load_config(config)
        else:
            self.config = AESConfig()

        # Parameters explicitly provided override config
        if key_size is None:
            key_size = self.config.key_size
        if enable_logging is None:
            enable_logging = self.config.enable_logging

        # Store default padding preference from config
        self._default_padding = self.config.padding

        # Configure logging
        if enable_logging:
            level_map = {
                "DEBUG": logging.DEBUG,
                "INFO": logging.INFO,
                "WARNING": logging.WARNING,
                "ERROR": logging.ERROR,
                "CRITICAL": logging.CRITICAL,
            }
            log_level = level_map.get(self.config.logging_level, logging.INFO)
            self.logger.setLevel(log_level)

        # Validate parameters
        if key_size not in (128, 192, 256):
            self.logger.error(f"Invalid key size: {key_size}")
            raise ValueError("Key size must be 128, 192, or 256 bits")

        if len(key) != key_size // 8:
            self.logger.error(
                f"Key length mismatch: expected {key_size // 8} bytes, "
                f"got {len(key)}"
            )
            raise ValueError(
                f"Key must be {key_size // 8} bytes for {key_size}-bit AES"
            )

        self.key_size = key_size
        self.nr = {128: 10, 192: 12, 256: 14}[key_size]
        self.expanded_key = expand_key(key, key_size)

        self.logger.info(
            f"AES cipher initialized with {key_size}-bit key ({self.nr} rounds)"
        )

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
        self.logger.debug(f"Encrypting block: {plaintext.hex()}")
        state = self._bytes_to_state(plaintext)

        # Initial round
        self.logger.debug("Initial round: AddRoundKey")
        add_round_key(state, get_round_key(self.expanded_key, 0))

        # Main rounds
        for round_num in range(1, self.nr):
            self.logger.debug(
                f"Round {round_num}: SubBytes, ShiftRows, MixColumns, AddRoundKey"
            )
            sub_bytes(state)
            shift_rows(state)
            mix_columns(state)
            add_round_key(state, get_round_key(self.expanded_key, round_num))

        # Final round (no MixColumns)
        self.logger.debug(f"Final round {self.nr}: SubBytes, ShiftRows, AddRoundKey")
        sub_bytes(state)
        shift_rows(state)
        add_round_key(state, get_round_key(self.expanded_key, self.nr))

        ciphertext = self._state_to_bytes(state)
        self.logger.debug(f"Block encrypted: {ciphertext.hex()}")
        return ciphertext

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
        self.logger.debug(f"Decrypting block: {ciphertext.hex()}")
        state = self._bytes_to_state(ciphertext)

        # Initial round
        self.logger.debug("Initial round: AddRoundKey")
        add_round_key(state, get_round_key(self.expanded_key, self.nr))

        # Main rounds
        for round_num in range(self.nr - 1, 0, -1):
            self.logger.debug(
                f"Round {round_num}: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns"
            )
            inv_shift_rows(state)
            inv_sub_bytes(state)
            add_round_key(state, get_round_key(self.expanded_key, round_num))
            inv_mix_columns(state)

        # Final round (no InvMixColumns)
        self.logger.debug("Final round: InvShiftRows, InvSubBytes, AddRoundKey")
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, get_round_key(self.expanded_key, 0))

        plaintext = self._state_to_bytes(state)
        self.logger.debug(f"Block decrypted: {plaintext.hex()}")
        return plaintext

    def encrypt(self, plaintext: bytes, padding: Optional[bool] = None) -> bytes:
        """
        Encrypt data with optional PKCS7 padding.

        Args:
            plaintext: Data to encrypt
            padding: Whether to apply PKCS7 padding.
                    If None, uses config default.

        Returns:
            Encrypted ciphertext
        """
        if padding is None:
            padding = self._default_padding

        self.logger.info(f"Starting encryption of {len(plaintext)} bytes")

        if padding:
            plaintext = self._pad(plaintext)
            self.logger.debug(
                f"Applied PKCS7 padding, new length: {len(plaintext)} bytes"
            )
        elif len(plaintext) % 16 != 0:
            self.logger.error(
                f"Invalid plaintext length: {len(plaintext)} "
                f"(must be multiple of 16)"
            )
            raise ValueError(
                "Plaintext length must be multiple of 16 when padding is disabled"
            )

        num_blocks = len(plaintext) // 16
        self.logger.debug(f"Encrypting {num_blocks} blocks")

        ciphertext = b""
        for i in range(0, len(plaintext), 16):
            block = plaintext[i : i + 16]
            ciphertext += self.encrypt_block(block)

        self.logger.info(f"Encryption complete: {len(ciphertext)} bytes")
        return ciphertext

    def decrypt(self, ciphertext: bytes, padding: Optional[bool] = None) -> bytes:
        """
        Decrypt data with optional PKCS7 unpadding.

        Args:
            ciphertext: Data to decrypt
            padding: Whether to remove PKCS7 padding.
                    If None, uses config default.

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If ciphertext length is not a multiple of 16
        """
        if padding is None:
            padding = self._default_padding

        self.logger.info(f"Starting decryption of {len(ciphertext)} bytes")

        if len(ciphertext) % 16 != 0:
            self.logger.error(
                f"Invalid ciphertext length: {len(ciphertext)} "
                f"(must be multiple of 16)"
            )
            raise ValueError("Ciphertext length must be multiple of 16")

        num_blocks = len(ciphertext) // 16
        self.logger.debug(f"Decrypting {num_blocks} blocks")

        plaintext = b""
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i : i + 16]
            plaintext += self.decrypt_block(block)

        if padding:
            plaintext = self._unpad(plaintext)
            self.logger.debug("Removed PKCS7 padding")

        self.logger.info(f"Decryption complete: {len(plaintext)} bytes")
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

        if len(data) < padding_length:
            raise ValueError("Invalid padding")

        # Verify padding
        for i in range(padding_length):
            if data[-1 - i] != padding_length:
                raise ValueError("Invalid padding")

        return data[:-padding_length]
