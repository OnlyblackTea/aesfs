# AESFS Architecture

This document explains the design principles and architecture of the AESFS implementation.

## Design Principles

### High Cohesion

Each module in AESFS has a **single, well-defined responsibility**:

1. **`constants.py`** - Contains only lookup tables
   - S-box and inverse S-box for SubBytes transformation
   - Round constants (RCON) for key expansion
   - No logic, just data

2. **`galois_field.py`** - Handles only Galois Field GF(2^8) arithmetic
   - Multiplication operations in GF(2^8)
   - Optimized functions for common multipliers (2, 3, 9, 11, 13, 14)
   - No dependencies on other modules

3. **`transformations.py`** - Implements only the four AES transformations
   - SubBytes and InvSubBytes
   - ShiftRows and InvShiftRows
   - MixColumns and InvMixColumns
   - AddRoundKey
   - Pure transformation logic, no orchestration

4. **`key_expansion.py`** - Handles only key scheduling
   - Key expansion algorithm
   - Round key extraction
   - No encryption/decryption logic

5. **`diffie_hellman.py`** - Implements Diffie-Hellman key exchange
   - Key generation (private and public keys)
   - Shared secret computation
   - Helper functions for modular arithmetic and prime checking
   - No dependencies on other AESFS modules

6. **`logger.py`** - Provides logging functionality
   - Logger configuration and setup
   - No dependencies on other AESFS modules
   - Uses Python's standard logging library

7. **`aes.py`** - Orchestrates encryption/decryption
   - High-level encrypt/decrypt methods
   - Padding management
   - Optional logging integration
   - Delegates to other modules for actual operations

### Low Coupling

Modules have **minimal dependencies** on each other:

```
constants.py    galois_field.py    logger.py    diffie_hellman.py
     ↓                 ↓                ↓                 (independent)
     └────────┬────────┘                ↓
              ↓                          ↓
      transformations.py                 ↓
              ↓                          ↓
              └──────────┐               ↓
                         ↓               ↓
      key_expansion.py → aes.py ←───────┘
```

Dependency rules:
- `constants.py` has no dependencies
- `galois_field.py` has no dependencies
- `diffie_hellman.py` has no dependencies on other AESFS modules
- `logger.py` has no dependencies on other AESFS modules
- `transformations.py` depends only on constants and galois_field
- `key_expansion.py` depends only on constants
- `aes.py` depends on transformations, key_expansion, and logger modules

## Module Details

### constants.py

**Purpose**: Provide lookup tables for AES operations

**Contents**:
- `SBOX`: 256-byte S-box for SubBytes
- `INV_SBOX`: 256-byte inverse S-box for InvSubBytes
- `RCON`: Round constants for key expansion

**Cohesion**: High - only contains constant data
**Coupling**: None - no dependencies

### galois_field.py

**Purpose**: Implement Galois Field GF(2^8) arithmetic

**Key Functions**:
- `gmul(a, b)`: General multiplication in GF(2^8)
- `gmul_2(x)`: Optimized multiplication by 2
- `gmul_3(x)`: Optimized multiplication by 3
- `gmul_9(x)`, `gmul_11(x)`, `gmul_13(x)`, `gmul_14(x)`: For InvMixColumns

**Cohesion**: High - only GF arithmetic
**Coupling**: None - no dependencies

### transformations.py

**Purpose**: Implement AES transformations

**Key Functions**:
- `sub_bytes(state)`: Apply S-box substitution
- `inv_sub_bytes(state)`: Apply inverse S-box substitution
- `shift_rows(state)`: Cyclically shift rows
- `inv_shift_rows(state)`: Inverse row shifting
- `mix_columns(state)`: Mix column data in GF(2^8)
- `inv_mix_columns(state)`: Inverse column mixing
- `add_round_key(state, round_key)`: XOR state with round key

**Cohesion**: High - only transformation operations
**Coupling**: Low - depends only on constants and galois_field

### key_expansion.py

**Purpose**: Expand cipher key into round keys

**Key Functions**:
- `rot_word(word)`: Rotate 4-byte word
- `sub_word(word)`: Apply S-box to word
- `expand_key(key, key_size)`: Expand key to all round keys
- `get_round_key(expanded_key, round_num)`: Extract specific round key

**Cohesion**: High - only key expansion logic
**Coupling**: Low - depends only on constants

### diffie_hellman.py

**Purpose**: Implement Diffie-Hellman key exchange protocol

**Key Classes**:
- `DiffieHellman`: Main class for key exchange

**Key Methods**:
- `__init__(prime, generator)`: Initialize with parameters (uses standard 2048-bit prime by default)
- `generate_private_key(key_size_bits)`: Generate a random private key
- `generate_public_key()`: Compute public key from private key
- `compute_shared_secret(other_public_key)`: Compute shared secret from other party's public key
- `get_shared_secret_bytes(byte_length)`: Convert shared secret to bytes for use as AES key

**Helper Functions**:
- `modular_exponentiation(base, exponent, modulus)`: Efficient modular exponentiation
- `is_prime(n, k)`: Miller-Rabin primality test
- `generate_parameters(bit_length)`: Generate custom DH parameters

**Constants**:
- `STANDARD_PRIME_2048`: RFC 3526 standard 2048-bit prime
- `STANDARD_GENERATOR`: Standard generator (2)

**Cohesion**: High - only key exchange logic
**Coupling**: None - no dependencies on other AESFS modules

**Use Case**:
Allows two parties to establish a shared secret over an insecure channel, which can then be used as an AES encryption key.

### logger.py

**Purpose**: Provide logging configuration and utilities

**Key Functions**:
- `setup_logger(name, level)`: Configure and return a logger
- `get_logger(name)`: Get an existing logger instance

**Cohesion**: High - only logging functionality
**Coupling**: None - no dependencies on other AESFS modules

**Features**:
- Configurable logging levels (DEBUG, INFO, WARNING, ERROR)
- Console output with timestamps
- Thread-safe logging for concurrent operations

### aes.py

**Purpose**: Provide high-level AES encryption/decryption interface

**Key Classes**:
- `AES`: Main cipher class

**Key Methods**:
- `__init__(key, key_size, enable_logging)`: Initialize with a key and optional logging
- `encrypt_block(plaintext)`: Encrypt single 16-byte block
- `decrypt_block(ciphertext)`: Decrypt single 16-byte block
- `encrypt(plaintext, padding)`: Encrypt data with optional padding
- `decrypt(ciphertext, padding)`: Decrypt data with optional padding
- `_pad(data)`: Apply PKCS7 padding
- `_unpad(data)`: Remove PKCS7 padding

**Logging Capabilities**:
- INFO level: Logs initialization, encryption/decryption start/complete
- DEBUG level: Logs detailed round-by-round operations
- ERROR level: Logs validation errors and exceptions

**Cohesion**: High - only orchestration, padding, and logging integration
**Coupling**: Medium - depends on transformations, key_expansion, and logger modules

## Design Benefits

### Maintainability
- Each module can be understood independently
- Changes to one module rarely affect others
- Easy to locate and fix bugs

### Testability
- Each module can be tested in isolation
- Mock dependencies easily due to clear interfaces
- 52 unit tests cover all functionality including logging and Diffie-Hellman

### Extensibility
- Easy to add new key sizes
- Can swap implementations of specific transformations
- Can add new modes of operation (CBC, CTR, etc.)
- Diffie-Hellman can be extended with custom parameter generation

### Readability
- Clear separation of concerns
- Each module is small and focused
- Easy for new developers to understand

## Testing Strategy

Each module has dedicated tests:

- `test_galois_field.py`: Tests GF arithmetic
- `test_transformations.py`: Tests each transformation and its inverse
- `test_key_expansion.py`: Tests key expansion for all key sizes
- `test_aes.py`: Tests end-to-end encryption/decryption
- `test_diffie_hellman.py`: Tests key exchange protocol and helper functions
- `test_logging.py`: Tests logging functionality

Tests verify:
- Correct functionality
- Inverse operations work correctly
- Error handling for invalid inputs
- Support for all key sizes (128, 192, 256 bits)
- Key exchange produces matching shared secrets

## Usage Examples

### Basic AES Encryption

```python
from aesfs import AES

# Create cipher with 128-bit key
key = b'This is a key123'
cipher = AES(key, key_size=128)

# Encrypt and decrypt
plaintext = b'Hello, World!'
ciphertext = cipher.encrypt(plaintext)
decrypted = cipher.decrypt(ciphertext)

assert decrypted == plaintext
```

### Diffie-Hellman Key Exchange with AES

```python
from aesfs import DiffieHellman, AES

# Alice and Bob perform key exchange
alice = DiffieHellman()
alice.generate_private_key()
alice_public = alice.generate_public_key()

bob = DiffieHellman()
bob.generate_private_key()
bob_public = bob.generate_public_key()

# Compute shared secrets
alice.compute_shared_secret(bob_public)
bob.compute_shared_secret(alice_public)

# Derive AES key and encrypt
aes_key = alice.get_shared_secret_bytes(32)
cipher = AES(aes_key, key_size=256)
ciphertext = cipher.encrypt(b'Secret message')
```

## Security Notice

This is an **educational implementation** designed to demonstrate clean architecture principles. For production use, please use established cryptographic libraries like `cryptography` or `pycryptodome` that have been thoroughly vetted for security.

Key limitations:
- No protection against timing attacks
- No secure key generation utilities (though DH uses cryptographically secure random)
- No support for modes of operation beyond ECB
- No hardware acceleration
- Diffie-Hellman shared secret derivation is simplified (use proper KDF in production)

## Future Enhancements

While maintaining high cohesion and low coupling, possible additions include:

1. **New Module: `modes.py`**
   - CBC, CTR, GCM modes
   - Would depend on `aes.py`
   - High cohesion: only mode implementations

2. **New Module: `utils.py`**
   - Key derivation functions
   - Random key generation
   - High cohesion: only utility functions

3. **Performance Optimizations**
   - Keep existing interfaces
   - Optimize internal implementations
   - Add optional C extensions

Each enhancement would follow the same principles: high cohesion (single responsibility) and low coupling (minimal dependencies).
