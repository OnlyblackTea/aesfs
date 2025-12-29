"""Tests for Diffie-Hellman key exchange."""

import unittest
from aesfs.diffie_hellman import (
    DiffieHellman, 
    modular_exponentiation, 
    is_prime,
    STANDARD_PRIME_2048,
    STANDARD_GENERATOR
)


class TestDiffieHellman(unittest.TestCase):
    """Test Diffie-Hellman key exchange."""
    
    def test_initialization_with_defaults(self):
        """Test DH initialization with default parameters."""
        dh = DiffieHellman()
        self.assertEqual(dh.prime, STANDARD_PRIME_2048)
        self.assertEqual(dh.generator, STANDARD_GENERATOR)
        self.assertIsNone(dh.get_private_key())
        self.assertIsNone(dh.get_public_key())
        self.assertIsNone(dh.get_shared_secret())
    
    def test_initialization_with_custom_params(self):
        """Test DH initialization with custom parameters."""
        prime = 23  # Small prime for testing
        generator = 5
        dh = DiffieHellman(prime=prime, generator=generator)
        self.assertEqual(dh.prime, prime)
        self.assertEqual(dh.generator, generator)
    
    def test_invalid_prime(self):
        """Test error handling for invalid prime."""
        with self.assertRaises(ValueError):
            DiffieHellman(prime=1, generator=2)
        
        with self.assertRaises(ValueError):
            DiffieHellman(prime=0, generator=2)
    
    def test_invalid_generator(self):
        """Test error handling for invalid generator."""
        with self.assertRaises(ValueError):
            DiffieHellman(prime=23, generator=0)
        
        with self.assertRaises(ValueError):
            DiffieHellman(prime=23, generator=23)
        
        with self.assertRaises(ValueError):
            DiffieHellman(prime=23, generator=25)
    
    def test_generate_private_key(self):
        """Test private key generation."""
        dh = DiffieHellman(prime=23, generator=5)
        private_key = dh.generate_private_key()
        
        self.assertIsNotNone(private_key)
        self.assertGreaterEqual(private_key, 2)
        self.assertLessEqual(private_key, 21)  # prime - 2
        self.assertEqual(dh.get_private_key(), private_key)
    
    def test_set_private_key(self):
        """Test setting a custom private key."""
        dh = DiffieHellman(prime=23, generator=5)
        dh.set_private_key(10)
        self.assertEqual(dh.get_private_key(), 10)
    
    def test_set_invalid_private_key(self):
        """Test error handling for invalid private key."""
        dh = DiffieHellman(prime=23, generator=5)
        
        with self.assertRaises(ValueError):
            dh.set_private_key(0)
        
        with self.assertRaises(ValueError):
            dh.set_private_key(1)
        
        with self.assertRaises(ValueError):
            dh.set_private_key(22)  # prime - 1
        
        with self.assertRaises(ValueError):
            dh.set_private_key(23)  # prime
    
    def test_generate_public_key(self):
        """Test public key generation."""
        dh = DiffieHellman(prime=23, generator=5)
        dh.set_private_key(6)
        public_key = dh.generate_public_key()
        
        # Public key should be g^private_key mod p = 5^6 mod 23 = 8
        self.assertEqual(public_key, 8)
        self.assertEqual(dh.get_public_key(), 8)
    
    def test_generate_public_key_without_private_key(self):
        """Test error when generating public key without private key."""
        dh = DiffieHellman(prime=23, generator=5)
        
        with self.assertRaises(ValueError):
            dh.generate_public_key()
    
    def test_compute_shared_secret(self):
        """Test computing shared secret."""
        dh = DiffieHellman(prime=23, generator=5)
        dh.set_private_key(6)
        
        # Other party's public key
        other_public_key = 19
        
        # Compute shared secret
        shared_secret = dh.compute_shared_secret(other_public_key)
        
        # Shared secret should be other_public_key^private_key mod p
        # = 19^6 mod 23 = 2
        self.assertEqual(shared_secret, 2)
        self.assertEqual(dh.get_shared_secret(), 2)
    
    def test_compute_shared_secret_without_private_key(self):
        """Test error when computing shared secret without private key."""
        dh = DiffieHellman(prime=23, generator=5)
        
        with self.assertRaises(ValueError):
            dh.compute_shared_secret(10)
    
    def test_compute_shared_secret_with_invalid_other_key(self):
        """Test error handling for invalid other public key."""
        dh = DiffieHellman(prime=23, generator=5)
        dh.set_private_key(6)
        
        with self.assertRaises(ValueError):
            dh.compute_shared_secret(0)
        
        with self.assertRaises(ValueError):
            dh.compute_shared_secret(1)
        
        with self.assertRaises(ValueError):
            dh.compute_shared_secret(23)
        
        with self.assertRaises(ValueError):
            dh.compute_shared_secret(25)
    
    def test_key_exchange_between_two_parties(self):
        """Test complete key exchange between Alice and Bob."""
        # Both parties agree on the same prime and generator
        prime = 23
        generator = 5
        
        # Alice's side
        alice = DiffieHellman(prime=prime, generator=generator)
        alice.set_private_key(6)
        alice_public = alice.generate_public_key()
        
        # Bob's side
        bob = DiffieHellman(prime=prime, generator=generator)
        bob.set_private_key(15)
        bob_public = bob.generate_public_key()
        
        # Exchange public keys and compute shared secrets
        alice_shared = alice.compute_shared_secret(bob_public)
        bob_shared = bob.compute_shared_secret(alice_public)
        
        # Both should have the same shared secret
        self.assertEqual(alice_shared, bob_shared)
    
    def test_key_exchange_with_standard_params(self):
        """Test key exchange with standard 2048-bit parameters."""
        # Alice
        alice = DiffieHellman()
        alice.generate_private_key()
        alice_public = alice.generate_public_key()
        
        # Bob
        bob = DiffieHellman()
        bob.generate_private_key()
        bob_public = bob.generate_public_key()
        
        # Compute shared secrets
        alice_shared = alice.compute_shared_secret(bob_public)
        bob_shared = bob.compute_shared_secret(alice_public)
        
        # Both should have the same shared secret
        self.assertEqual(alice_shared, bob_shared)
        
        # The shared secret should be a large number
        self.assertGreater(alice_shared, 0)
    
    def test_get_shared_secret_bytes(self):
        """Test converting shared secret to bytes."""
        dh = DiffieHellman(prime=23, generator=5)
        dh.set_private_key(6)
        dh.compute_shared_secret(19)
        
        # Test different byte lengths
        for byte_length in [16, 24, 32]:
            secret_bytes = dh.get_shared_secret_bytes(byte_length)
            self.assertEqual(len(secret_bytes), byte_length)
            self.assertIsInstance(secret_bytes, bytes)
    
    def test_get_shared_secret_bytes_without_secret(self):
        """Test error when getting bytes without computing shared secret."""
        dh = DiffieHellman(prime=23, generator=5)
        
        with self.assertRaises(ValueError):
            dh.get_shared_secret_bytes()
    
    def test_private_key_reset_on_set(self):
        """Test that public key and shared secret are reset when private key changes."""
        dh = DiffieHellman(prime=23, generator=5)
        dh.set_private_key(6)
        dh.generate_public_key()
        dh.compute_shared_secret(19)
        
        # All should be set
        self.assertIsNotNone(dh.get_private_key())
        self.assertIsNotNone(dh.get_public_key())
        self.assertIsNotNone(dh.get_shared_secret())
        
        # Change private key
        dh.set_private_key(7)
        
        # Private key should be updated, others should be reset
        self.assertEqual(dh.get_private_key(), 7)
        self.assertIsNone(dh.get_public_key())
        self.assertIsNone(dh.get_shared_secret())


class TestHelperFunctions(unittest.TestCase):
    """Test helper functions."""
    
    def test_modular_exponentiation(self):
        """Test modular exponentiation."""
        # Test cases
        self.assertEqual(modular_exponentiation(5, 6, 23), 8)
        self.assertEqual(modular_exponentiation(2, 10, 1000), 24)
        self.assertEqual(modular_exponentiation(3, 7, 11), 9)
    
    def test_is_prime(self):
        """Test prime number checking."""
        # Known primes
        self.assertTrue(is_prime(2))
        self.assertTrue(is_prime(3))
        self.assertTrue(is_prime(5))
        self.assertTrue(is_prime(7))
        self.assertTrue(is_prime(11))
        self.assertTrue(is_prime(23))
        self.assertTrue(is_prime(97))
        
        # Known composites
        self.assertFalse(is_prime(0))
        self.assertFalse(is_prime(1))
        self.assertFalse(is_prime(4))
        self.assertFalse(is_prime(6))
        self.assertFalse(is_prime(8))
        self.assertFalse(is_prime(9))
        self.assertFalse(is_prime(15))
        self.assertFalse(is_prime(100))
    
    def test_is_prime_large_numbers(self):
        """Test prime checking with larger numbers."""
        # Large known prime
        large_prime = 2**31 - 1  # Mersenne prime
        self.assertTrue(is_prime(large_prime))
        
        # Large composite
        large_composite = 2**32 - 1
        self.assertFalse(is_prime(large_composite))


if __name__ == '__main__':
    unittest.main()
