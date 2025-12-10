"""Tests for configuration module."""

import json
import os
import tempfile
import unittest
from aesfs import AES, AESConfig, load_config


class TestAESConfig(unittest.TestCase):
    """Test AESConfig class."""

    def test_default_config(self):
        """Test default configuration values."""
        config = AESConfig()

        self.assertEqual(config.key_size, 128)
        self.assertTrue(config.padding)
        self.assertFalse(config.enable_logging)
        self.assertEqual(config.logging_level, "INFO")

    def test_config_from_dict(self):
        """Test configuration from dictionary."""
        config_dict = {
            "key_size": 256,
            "padding": False,
            "enable_logging": True,
            "logging_level": "DEBUG",
        }
        config = AESConfig(config_dict)

        self.assertEqual(config.key_size, 256)
        self.assertFalse(config.padding)
        self.assertTrue(config.enable_logging)
        self.assertEqual(config.logging_level, "DEBUG")

    def test_invalid_key_size(self):
        """Test validation of invalid key size."""
        with self.assertRaises(ValueError) as context:
            AESConfig({"key_size": 512})

        self.assertIn("Invalid key_size", str(context.exception))

    def test_invalid_logging_level(self):
        """Test validation of invalid logging level."""
        with self.assertRaises(ValueError) as context:
            AESConfig({"logging_level": "INVALID"})

        self.assertIn("Invalid logging_level", str(context.exception))

    def test_to_dict(self):
        """Test conversion to dictionary."""
        config = AESConfig({"key_size": 192, "padding": False})
        config_dict = config.to_dict()

        self.assertEqual(config_dict["key_size"], 192)
        self.assertFalse(config_dict["padding"])
        self.assertFalse(config_dict["enable_logging"])
        self.assertEqual(config_dict["logging_level"], "INFO")

    def test_from_json_file(self):
        """Test loading configuration from JSON file."""
        config_data = {
            "key_size": 256,
            "padding": True,
            "enable_logging": True,
            "logging_level": "WARNING",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_file = f.name

        try:
            config = AESConfig.from_json_file(temp_file)

            self.assertEqual(config.key_size, 256)
            self.assertTrue(config.padding)
            self.assertTrue(config.enable_logging)
            self.assertEqual(config.logging_level, "WARNING")
        finally:
            os.unlink(temp_file)

    def test_from_json_file_not_found(self):
        """Test error when JSON file doesn't exist."""
        with self.assertRaises(FileNotFoundError):
            AESConfig.from_json_file("/nonexistent/file.json")

    def test_from_file_auto_detect(self):
        """Test auto-detection of file format."""
        config_data = {"key_size": 192, "padding": False}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_file = f.name

        try:
            config = AESConfig.from_file(temp_file)
            self.assertEqual(config.key_size, 192)
            self.assertFalse(config.padding)
        finally:
            os.unlink(temp_file)

    def test_from_file_unsupported_format(self):
        """Test error with unsupported file format."""
        with self.assertRaises(ValueError) as context:
            AESConfig.from_file("config.txt")

        self.assertIn("Unsupported configuration file format", str(context.exception))


class TestLoadConfig(unittest.TestCase):
    """Test load_config convenience function."""

    def test_load_none(self):
        """Test loading with None returns default config."""
        config = load_config(None)

        self.assertIsInstance(config, AESConfig)
        self.assertEqual(config.key_size, 128)

    def test_load_dict(self):
        """Test loading from dictionary."""
        config = load_config({"key_size": 256})

        self.assertIsInstance(config, AESConfig)
        self.assertEqual(config.key_size, 256)

    def test_load_config_instance(self):
        """Test loading from AESConfig instance."""
        original = AESConfig({"key_size": 192})
        config = load_config(original)

        self.assertIs(config, original)
        self.assertEqual(config.key_size, 192)

    def test_load_from_file(self):
        """Test loading from file path."""
        config_data = {"key_size": 256, "padding": False}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_file = f.name

        try:
            config = load_config(temp_file)

            self.assertIsInstance(config, AESConfig)
            self.assertEqual(config.key_size, 256)
            self.assertFalse(config.padding)
        finally:
            os.unlink(temp_file)

    def test_load_invalid_type(self):
        """Test error with invalid config source type."""
        with self.assertRaises(TypeError):
            load_config(12345)


class TestAESWithConfig(unittest.TestCase):
    """Test AES class with configuration support."""

    def test_aes_with_dict_config(self):
        """Test AES with dictionary configuration."""
        config = {"key_size": 128, "padding": True}
        key = b"This is a key123"

        cipher = AES(key, config=config)

        plaintext = b"Test message"
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)

        self.assertEqual(decrypted, plaintext)

    def test_aes_with_config_object(self):
        """Test AES with AESConfig object."""
        config = AESConfig({"key_size": 192, "padding": True})
        key = b"192bitkey_24byteshere!!!"  # Exactly 24 bytes

        cipher = AES(key, config=config)

        plaintext = b"Test with config object"
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)

        self.assertEqual(decrypted, plaintext)

    def test_aes_with_config_file(self):
        """Test AES with configuration file."""
        config_data = {"key_size": 256, "padding": True, "enable_logging": False}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_file = f.name

        try:
            key = b"0123456789abcdef0123456789abcdef"
            cipher = AES(key, config=temp_file)

            plaintext = b"Config file test"
            ciphertext = cipher.encrypt(plaintext)
            decrypted = cipher.decrypt(ciphertext)

            self.assertEqual(decrypted, plaintext)
        finally:
            os.unlink(temp_file)

    def test_aes_explicit_params_override_config(self):
        """Test that explicit parameters override config."""
        config = {"key_size": 256, "padding": False}
        key = b"This is a key123"

        # key_size explicitly set to 128, overriding config's 256
        cipher = AES(key, key_size=128, config=config)

        self.assertEqual(cipher.key_size, 128)

    def test_aes_backward_compatibility(self):
        """Test backward compatibility without config."""
        key = b"This is a key123"

        # Old-style initialization should still work
        cipher = AES(key, key_size=128, enable_logging=False)

        plaintext = b"Backward compatible"
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)

        self.assertEqual(decrypted, plaintext)

    def test_aes_default_padding_from_config(self):
        """Test that default padding comes from config."""
        config = {"key_size": 128, "padding": False}
        key = b"This is a key123"

        cipher = AES(key, config=config)

        # Should use config's padding=False by default
        plaintext = b"Exactly16BytesXX"  # Exactly 16 bytes
        ciphertext = cipher.encrypt(plaintext)  # No padding arg
        decrypted = cipher.decrypt(ciphertext)  # No padding arg

        self.assertEqual(decrypted, plaintext)

    def test_aes_padding_override(self):
        """Test that padding parameter overrides config."""
        config = {"key_size": 128, "padding": False}
        key = b"This is a key123"

        cipher = AES(key, config=config)

        # Override config's padding=False with explicit padding=True
        plaintext = b"Short message"
        ciphertext = cipher.encrypt(plaintext, padding=True)
        decrypted = cipher.decrypt(ciphertext, padding=True)

        self.assertEqual(decrypted, plaintext)


if __name__ == "__main__":
    unittest.main()
