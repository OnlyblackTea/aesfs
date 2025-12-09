"""Tests for logging functionality."""

import unittest
import logging
from io import StringIO
from aesfs import AES, setup_logger


class TestLogging(unittest.TestCase):
    """Test logging functionality."""
    
    def test_logging_disabled_by_default(self):
        """Test that logging is disabled by default."""
        key = b'This is a key123'
        cipher = AES(key, key_size=128)
        
        # Logger should be at NOTSET level by default (inherits from root logger)
        # When enable_logging is False, we don't change the logger level
        self.assertIn(cipher.logger.level, [logging.NOTSET, logging.WARNING])
    
    def test_logging_enabled(self):
        """Test that logging can be enabled."""
        key = b'This is a key123'
        cipher = AES(key, key_size=128, enable_logging=True)
        
        # Logger should be at INFO level when enabled
        self.assertEqual(cipher.logger.level, logging.INFO)
    
    def test_setup_logger(self):
        """Test logger setup function."""
        logger = setup_logger("test_logger", level=logging.DEBUG)
        
        self.assertEqual(logger.name, "test_logger")
        self.assertEqual(logger.level, logging.DEBUG)
        self.assertTrue(len(logger.handlers) > 0)
    
    def test_logging_output(self):
        """Test that logging produces output when enabled."""
        # Set up a string stream to capture log output
        log_stream = StringIO()
        handler = logging.StreamHandler(log_stream)
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        
        # Create logger and add our handler
        logger = logging.getLogger("aesfs")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        
        # Create cipher with logging enabled
        key = b'This is a key123'
        cipher = AES(key, key_size=128, enable_logging=True)
        plaintext = b'Hello, World!'
        
        # Perform encryption
        cipher.encrypt(plaintext)
        
        # Check that log messages were generated
        log_output = log_stream.getvalue()
        self.assertIn("AES cipher initialized", log_output)
        self.assertIn("Starting encryption", log_output)
        
        # Clean up
        logger.removeHandler(handler)
        logger.setLevel(logging.WARNING)


if __name__ == '__main__':
    unittest.main()
