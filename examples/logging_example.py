"""
Logging example for the AESFS library.

This example demonstrates how to enable and use logging
to track AES encryption and decryption operations.
"""

import logging
from aesfs import AES, setup_logger


def example_basic_logging():
    """Example: Basic logging with default INFO level."""
    print("=" * 60)
    print("Example 1: Basic Logging (INFO level)")
    print("=" * 60)
    
    key = b'This is a key123'
    
    # Create AES cipher with logging enabled
    cipher = AES(key, key_size=128, enable_logging=True)
    
    plaintext = b'Hello, World!'
    print(f"\nPlaintext: {plaintext}")
    
    # Encrypt - logging will show the process
    ciphertext = cipher.encrypt(plaintext)
    print(f"Ciphertext: {ciphertext.hex()}")
    
    # Decrypt - logging will show the process
    decrypted = cipher.decrypt(ciphertext)
    print(f"Decrypted: {decrypted}")
    print()


def example_detailed_logging():
    """Example: Detailed logging with DEBUG level."""
    print("=" * 60)
    print("Example 2: Detailed Logging (DEBUG level)")
    print("=" * 60)
    
    # Set up logger with DEBUG level for detailed output
    logger = setup_logger("aesfs", level=logging.DEBUG)
    
    key = b'SecretKey1234567'
    cipher = AES(key, key_size=128, enable_logging=True)
    
    plaintext = b'Short message'
    print(f"\nPlaintext: {plaintext}")
    
    # This will show detailed round-by-round operations
    ciphertext = cipher.encrypt(plaintext)
    print(f"\nCiphertext: {ciphertext.hex()}")
    print()


def example_no_logging():
    """Example: No logging (default behavior)."""
    print("=" * 60)
    print("Example 3: No Logging (default)")
    print("=" * 60)
    
    key = b'This is a key123'
    
    # Create AES cipher without logging enabled
    cipher = AES(key, key_size=128)
    
    plaintext = b'Silent operation'
    print(f"\nPlaintext: {plaintext}")
    
    # No logging output will be shown
    ciphertext = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(ciphertext)
    
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Decrypted: {decrypted}")
    print(f"Success: {plaintext == decrypted}")
    print()


def example_error_logging():
    """Example: Logging errors and validation."""
    print("=" * 60)
    print("Example 4: Error Logging")
    print("=" * 60)
    
    # Set up logger to see error messages
    setup_logger("aesfs", level=logging.ERROR)
    
    key = b'This is a key123'
    cipher = AES(key, key_size=128, enable_logging=True)
    
    print("\nAttempting invalid operations...")
    
    # Try to encrypt data with wrong length (without padding)
    try:
        invalid_plaintext = b'Not 16 bytes'
        cipher.encrypt(invalid_plaintext, padding=False)
    except ValueError as e:
        print(f"Caught expected error: {e}")
    
    print()


def main():
    """Run all logging examples."""
    print("\n" + "=" * 60)
    print("AESFS - Logging System Examples")
    print("=" * 60 + "\n")
    
    example_basic_logging()
    example_detailed_logging()
    example_no_logging()
    example_error_logging()
    
    print("=" * 60)
    print("All logging examples completed!")
    print("=" * 60)


if __name__ == '__main__':
    main()
