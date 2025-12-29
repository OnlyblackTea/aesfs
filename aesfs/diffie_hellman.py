"""
Diffie-Hellman Key Exchange Module

This module implements the Diffie-Hellman key exchange protocol.
High cohesion: Contains only Diffie-Hellman key exchange logic.
Low coupling: Has no dependencies on other aesfs modules.
"""

import secrets
from typing import Tuple


# Standard Diffie-Hellman parameters (RFC 3526 - 2048-bit MODP Group)
# These are safe primes commonly used in production
STANDARD_PRIME_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)

STANDARD_GENERATOR = 2


class DiffieHellman:
    """
    Diffie-Hellman key exchange implementation.
    
    This class allows two parties to establish a shared secret over an
    insecure channel. Each party generates a private key and computes
    a public key. After exchanging public keys, both parties can compute
    the same shared secret.
    
    Security Note:
    - Use large primes (at least 2048 bits) for production
    - Private keys should be kept secret
    - This implementation is for educational purposes
    """
    
    def __init__(self, prime: int = None, generator: int = None):
        """
        Initialize Diffie-Hellman with prime and generator.
        
        Args:
            prime: A large prime number (p). If None, uses standard 2048-bit prime.
            generator: A generator (g) of the multiplicative group mod p.
                      If None, uses standard generator (2).
        
        Raises:
            ValueError: If prime or generator is invalid
        """
        self.prime = prime if prime is not None else STANDARD_PRIME_2048
        self.generator = generator if generator is not None else STANDARD_GENERATOR
        
        # Validate parameters
        if self.prime <= 1:
            raise ValueError("Prime must be greater than 1")
        if self.generator <= 0 or self.generator >= self.prime:
            raise ValueError(f"Generator must be between 1 and {self.prime - 1}")
        
        # Private and public keys (initially None)
        self._private_key = None
        self._public_key = None
        self._shared_secret = None
    
    def generate_private_key(self, key_size_bits: int = None) -> int:
        """
        Generate a random private key.
        
        Args:
            key_size_bits: Size of the private key in bits.
                          If None, uses the bit length of the prime minus 1.
        
        Returns:
            The generated private key
        """
        if key_size_bits is None:
            key_size_bits = self.prime.bit_length() - 1
        
        # Generate a random private key in range [2, prime-2]
        # We avoid 0, 1, and prime-1 for security reasons
        self._private_key = secrets.randbelow(self.prime - 3) + 2
        return self._private_key
    
    def get_private_key(self) -> int:
        """
        Get the private key.
        
        Returns:
            The private key, or None if not generated
        """
        return self._private_key
    
    def set_private_key(self, private_key: int) -> None:
        """
        Set a custom private key.
        
        Args:
            private_key: The private key to use
        
        Raises:
            ValueError: If private key is invalid
        """
        if private_key <= 1 or private_key >= self.prime - 1:
            raise ValueError(f"Private key must be between 2 and {self.prime - 2}")
        
        self._private_key = private_key
        # Reset public key and shared secret as they depend on private key
        self._public_key = None
        self._shared_secret = None
    
    def generate_public_key(self) -> int:
        """
        Generate the public key from the private key.
        
        The public key is computed as: g^private_key mod p
        
        Returns:
            The generated public key
        
        Raises:
            ValueError: If private key hasn't been generated yet
        """
        if self._private_key is None:
            raise ValueError("Private key must be generated first")
        
        self._public_key = pow(self.generator, self._private_key, self.prime)
        return self._public_key
    
    def get_public_key(self) -> int:
        """
        Get the public key.
        
        Returns:
            The public key, or None if not generated
        """
        return self._public_key
    
    def compute_shared_secret(self, other_public_key: int) -> int:
        """
        Compute the shared secret using the other party's public key.
        
        The shared secret is computed as: other_public_key^private_key mod p
        
        Args:
            other_public_key: The public key received from the other party
        
        Returns:
            The computed shared secret
        
        Raises:
            ValueError: If private key hasn't been generated or if other_public_key is invalid
        """
        if self._private_key is None:
            raise ValueError("Private key must be generated first")
        
        if other_public_key <= 1 or other_public_key >= self.prime:
            raise ValueError(f"Other public key must be between 2 and {self.prime - 1}")
        
        self._shared_secret = pow(other_public_key, self._private_key, self.prime)
        return self._shared_secret
    
    def get_shared_secret(self) -> int:
        """
        Get the computed shared secret.
        
        Returns:
            The shared secret, or None if not computed yet
        """
        return self._shared_secret
    
    def get_shared_secret_bytes(self, byte_length: int = 32) -> bytes:
        """
        Get the shared secret as bytes, suitable for use as an AES key.
        
        Args:
            byte_length: Desired length in bytes (16, 24, or 32 for AES-128/192/256)
        
        Returns:
            The shared secret as bytes, truncated or padded to byte_length
        
        Raises:
            ValueError: If shared secret hasn't been computed yet
        """
        if self._shared_secret is None:
            raise ValueError("Shared secret must be computed first")
        
        # Convert the shared secret to bytes
        secret_bytes = self._shared_secret.to_bytes(
            (self._shared_secret.bit_length() + 7) // 8, 
            byteorder='big'
        )
        
        # Use a simple derivation: hash-like truncation or padding
        if len(secret_bytes) >= byte_length:
            # Truncate to desired length
            return secret_bytes[:byte_length]
        else:
            # Pad with zeros if too short (not ideal for production)
            return secret_bytes.ljust(byte_length, b'\x00')


def modular_exponentiation(base: int, exponent: int, modulus: int) -> int:
    """
    Compute (base^exponent) mod modulus efficiently.
    
    This is a helper function that uses Python's built-in pow() function
    which implements efficient modular exponentiation.
    
    Args:
        base: The base number
        exponent: The exponent
        modulus: The modulus
    
    Returns:
        (base^exponent) mod modulus
    """
    return pow(base, exponent, modulus)


def is_prime(n: int, k: int = 5) -> bool:
    """
    Test if a number is prime using Miller-Rabin primality test.
    
    This is a probabilistic test. With k rounds, the probability of
    a composite number passing the test is at most 4^(-k).
    
    Args:
        n: The number to test
        k: Number of rounds (higher = more accurate, default: 5)
    
    Returns:
        True if n is probably prime, False if definitely composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Miller-Rabin test
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def generate_parameters(bit_length: int = 2048) -> Tuple[int, int]:
    """
    Generate Diffie-Hellman parameters (prime and generator).
    
    WARNING: This is computationally expensive and should be done rarely.
    For most applications, use the standard parameters provided.
    
    Args:
        bit_length: Bit length of the prime (minimum 1024, recommended 2048+)
    
    Returns:
        A tuple (prime, generator)
    
    Raises:
        ValueError: If bit_length is too small
    """
    if bit_length < 1024:
        raise ValueError("Bit length must be at least 1024 for security")
    
    # For simplicity, we use generator = 2
    # In production, you would generate a safe prime p = 2q + 1
    # This is a simplified version for educational purposes
    generator = 2
    
    # Generate a random prime
    # Note: This is a simplified approach. In production, use cryptographic libraries
    while True:
        # Generate a random odd number
        prime = secrets.randbits(bit_length)
        prime |= (1 << bit_length - 1) | 1  # Set MSB and LSB to 1
        
        if is_prime(prime):
            return prime, generator
