"""
Diffie-Hellman key exchange examples for the AESFS library.

This example demonstrates how to use Diffie-Hellman key exchange
to establish a shared secret and use it for AES encryption.
"""

from aesfs import AES
from aesfs.diffie_hellman import DiffieHellman


def example_basic_key_exchange():
    """Example: Basic Diffie-Hellman key exchange."""
    print("=" * 60)
    print("Example 1: Basic Diffie-Hellman Key Exchange")
    print("=" * 60)
    
    # Simulate two parties: Alice and Bob
    # They agree on using standard parameters (this would be public knowledge)
    
    # Alice generates her keys
    alice = DiffieHellman()
    alice.generate_private_key()
    alice_public = alice.generate_public_key()
    print(f"\nAlice's public key (first 50 digits): {str(alice_public)[:50]}...")
    
    # Bob generates his keys
    bob = DiffieHellman()
    bob.generate_private_key()
    bob_public = bob.generate_public_key()
    print(f"Bob's public key (first 50 digits):   {str(bob_public)[:50]}...")
    
    # They exchange public keys over an insecure channel
    # and compute the shared secret
    alice_shared = alice.compute_shared_secret(bob_public)
    bob_shared = bob.compute_shared_secret(alice_public)
    
    # Verify they have the same shared secret
    print(f"\nShared secrets match: {alice_shared == bob_shared}")
    print(f"Shared secret (first 50 digits): {str(alice_shared)[:50]}...")
    print()


def example_key_exchange_with_aes():
    """Example: Using Diffie-Hellman with AES encryption."""
    print("=" * 60)
    print("Example 2: Diffie-Hellman + AES Encryption")
    print("=" * 60)
    
    # Alice and Bob want to communicate securely
    
    # Step 1: Key exchange
    alice = DiffieHellman()
    alice.generate_private_key()
    alice_public = alice.generate_public_key()
    
    bob = DiffieHellman()
    bob.generate_private_key()
    bob_public = bob.generate_public_key()
    
    # Compute shared secrets
    alice.compute_shared_secret(bob_public)
    bob.compute_shared_secret(alice_public)
    
    # Step 2: Derive AES keys from shared secret
    # Both parties can now use the same key for AES encryption
    alice_aes_key = alice.get_shared_secret_bytes(32)  # 256-bit key
    bob_aes_key = bob.get_shared_secret_bytes(32)
    
    print(f"\nAES keys match: {alice_aes_key == bob_aes_key}")
    print(f"AES key (hex): {alice_aes_key.hex()}")
    
    # Step 3: Alice encrypts a message
    alice_cipher = AES(alice_aes_key, key_size=256)
    message = b"Hello Bob! This is a secret message."
    ciphertext = alice_cipher.encrypt(message)
    
    print(f"\nAlice's message: {message}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    
    # Step 4: Bob decrypts the message
    bob_cipher = AES(bob_aes_key, key_size=256)
    decrypted = bob_cipher.decrypt(ciphertext)
    
    print(f"Bob decrypted: {decrypted}")
    print(f"Decryption successful: {message == decrypted}")
    print()


def example_custom_parameters():
    """Example: Using custom Diffie-Hellman parameters."""
    print("=" * 60)
    print("Example 3: Custom Diffie-Hellman Parameters")
    print("=" * 60)
    
    # For demonstration, using a small prime
    # (In production, always use large primes!)
    prime = 23
    generator = 5
    
    print(f"\nUsing custom parameters:")
    print(f"Prime (p): {prime}")
    print(f"Generator (g): {generator}")
    
    # Alice
    alice = DiffieHellman(prime=prime, generator=generator)
    alice.set_private_key(6)
    alice_public = alice.generate_public_key()
    print(f"\nAlice's private key: {alice.get_private_key()}")
    print(f"Alice's public key: {alice_public}")
    
    # Bob
    bob = DiffieHellman(prime=prime, generator=generator)
    bob.set_private_key(15)
    bob_public = bob.generate_public_key()
    print(f"\nBob's private key: {bob.get_private_key()}")
    print(f"Bob's public key: {bob_public}")
    
    # Compute shared secrets
    alice_shared = alice.compute_shared_secret(bob_public)
    bob_shared = bob.compute_shared_secret(alice_public)
    
    print(f"\nAlice's shared secret: {alice_shared}")
    print(f"Bob's shared secret: {bob_shared}")
    print(f"Secrets match: {alice_shared == bob_shared}")
    print()


def example_multiple_key_sizes():
    """Example: Deriving different AES key sizes from shared secret."""
    print("=" * 60)
    print("Example 4: Different AES Key Sizes from DH")
    print("=" * 60)
    
    # Perform key exchange
    alice = DiffieHellman()
    alice.generate_private_key()
    alice_public = alice.generate_public_key()
    
    bob = DiffieHellman()
    bob.generate_private_key()
    bob_public = bob.generate_public_key()
    
    alice.compute_shared_secret(bob_public)
    
    # Derive keys of different lengths
    key_128 = alice.get_shared_secret_bytes(16)  # AES-128
    key_192 = alice.get_shared_secret_bytes(24)  # AES-192
    key_256 = alice.get_shared_secret_bytes(32)  # AES-256
    
    print("\nDerived AES keys from shared secret:")
    print(f"AES-128 key (16 bytes): {key_128.hex()}")
    print(f"AES-192 key (24 bytes): {key_192.hex()}")
    print(f"AES-256 key (32 bytes): {key_256.hex()}")
    
    # Test encryption with each key size
    message = b"Testing different key sizes"
    
    for key_size, key in [(128, key_128), (192, key_192), (256, key_256)]:
        cipher = AES(key, key_size=key_size)
        ciphertext = cipher.encrypt(message)
        decrypted = cipher.decrypt(ciphertext)
        print(f"\nAES-{key_size}: Encryption {'✓' if decrypted == message else '✗'}")
    
    print()


def example_security_demonstration():
    """Example: Demonstrating security properties of DH."""
    print("=" * 60)
    print("Example 5: Security Demonstration")
    print("=" * 60)
    
    # Alice and Bob perform key exchange
    alice = DiffieHellman(prime=23, generator=5)
    alice.set_private_key(6)
    alice_public = alice.generate_public_key()
    
    bob = DiffieHellman(prime=23, generator=5)
    bob.set_private_key(15)
    bob_public = bob.generate_public_key()
    
    # An eavesdropper (Eve) can see:
    print("\nPublic information (visible to eavesdropper):")
    print(f"Prime (p): 23")
    print(f"Generator (g): 5")
    print(f"Alice's public key: {alice_public}")
    print(f"Bob's public key: {bob_public}")
    
    # But Eve cannot easily compute the shared secret
    alice_shared = alice.compute_shared_secret(bob_public)
    bob_shared = bob.compute_shared_secret(alice_public)
    
    print("\nPrivate information (NOT visible to eavesdropper):")
    print(f"Alice's private key: {alice.get_private_key()}")
    print(f"Bob's private key: {bob.get_private_key()}")
    print(f"Shared secret: {alice_shared}")
    
    print("\nNote: With large primes (2048+ bits), computing the")
    print("shared secret from public information is computationally infeasible.")
    print()


def main():
    """Run all examples."""
    print("\n" + "=" * 60)
    print("AESFS - Diffie-Hellman Key Exchange Examples")
    print("=" * 60 + "\n")
    
    example_basic_key_exchange()
    example_key_exchange_with_aes()
    example_custom_parameters()
    example_multiple_key_sizes()
    example_security_demonstration()
    
    print("=" * 60)
    print("All examples completed successfully!")
    print("=" * 60)


if __name__ == '__main__':
    main()
