"""
Basic usage examples for the AESFS library.
"""

from aesfs import AES


def example_basic_encryption():
    """Example: Basic encryption and decryption with AES-128."""
    print("=== Basic AES-128 Encryption ===")
    
    # Create a 128-bit (16-byte) key
    key = b'This is a key123'
    
    # Create AES cipher instance
    cipher = AES(key, key_size=128)
    
    # Encrypt a message
    plaintext = b'Hello, World! This is a secret message.'
    ciphertext = cipher.encrypt(plaintext)
    
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}")
    
    # Decrypt the message
    decrypted = cipher.decrypt(ciphertext)
    print(f"Decrypted:  {decrypted}")
    print()


def example_different_key_sizes():
    """Example: Using different AES key sizes."""
    print("=== Different Key Sizes ===")
    
    plaintext = b'Secret data'
    
    # AES-128
    key_128 = b'0123456789abcdef'
    cipher_128 = AES(key_128, key_size=128)
    ciphertext_128 = cipher_128.encrypt(plaintext)
    print(f"AES-128 ciphertext: {ciphertext_128.hex()}")
    
    # AES-192
    key_192 = b'0123456789abcdef01234567'
    cipher_192 = AES(key_192, key_size=192)
    ciphertext_192 = cipher_192.encrypt(plaintext)
    print(f"AES-192 ciphertext: {ciphertext_192.hex()}")
    
    # AES-256
    key_256 = b'0123456789abcdef0123456789abcdef'
    cipher_256 = AES(key_256, key_size=256)
    ciphertext_256 = cipher_256.encrypt(plaintext)
    print(f"AES-256 ciphertext: {ciphertext_256.hex()}")
    print()


def example_block_encryption():
    """Example: Encrypting a single 16-byte block."""
    print("=== Block Encryption ===")
    
    key = b'MySecretKey12345'
    cipher = AES(key, key_size=128)
    
    # Encrypt a single 16-byte block
    block = b'ExactlySixteenBB'
    ciphertext_block = cipher.encrypt_block(block)
    decrypted_block = cipher.decrypt_block(ciphertext_block)
    
    print(f"Original block:  {block}")
    print(f"Encrypted block: {ciphertext_block.hex()}")
    print(f"Decrypted block: {decrypted_block}")
    print()


def example_no_padding():
    """Example: Encryption without padding."""
    print("=== No Padding Mode ===")
    
    key = b'MySecretKey12345'
    cipher = AES(key, key_size=128)
    
    # Data must be exactly a multiple of 16 bytes when padding is disabled
    plaintext = b'0123456789ABCDEF' * 2  # Exactly 32 bytes
    
    ciphertext = cipher.encrypt(plaintext, padding=False)
    decrypted = cipher.decrypt(ciphertext, padding=False)
    
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Decrypted:  {decrypted}")
    print()


def main():
    """Run all examples."""
    print("AESFS - Simple AES Implementation Examples\n")
    
    example_basic_encryption()
    example_different_key_sizes()
    example_block_encryption()
    example_no_padding()
    
    print("All examples completed successfully!")


if __name__ == '__main__':
    main()
