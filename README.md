# AESFS - Simple AES Implementation

A clean, educational AES (Advanced Encryption Standard) implementation in Python with high cohesion and low coupling principles.

## Features

- **Modular Design**: Each component has a single, well-defined responsibility
- **Low Coupling**: Minimal dependencies between modules
- **Support for Multiple Key Sizes**: AES-128, AES-192, and AES-256
- **PKCS7 Padding**: Automatic padding for messages of any length
- **Diffie-Hellman Key Exchange**: Secure key agreement protocol for establishing shared secrets
- **Logging System**: Optional logging for debugging and monitoring encryption operations
- **Well-Tested**: Comprehensive test suite for all components
- **Pure Python**: No external dependencies required

## Architecture

The implementation is structured with clear separation of concerns:

- **`constants.py`**: Contains S-box, inverse S-box, and round constants
- **`galois_field.py`**: Galois Field GF(2^8) arithmetic operations
- **`transformations.py`**: Core AES transformations (SubBytes, ShiftRows, MixColumns, AddRoundKey)
- **`key_expansion.py`**: Key expansion algorithm
- **`diffie_hellman.py`**: Diffie-Hellman key exchange protocol
- **`logger.py`**: Logging configuration and utilities
- **`aes.py`**: Main AES cipher orchestrating all components

## Installation

```bash
python setup.py install
```

Or for development:

```bash
pip install -e .
```

## Usage

### Basic Encryption/Decryption

```python
from aesfs import AES

# Create a 128-bit key
key = b'This is a key123'

# Initialize AES cipher
cipher = AES(key, key_size=128)

# Encrypt a message
plaintext = b'Hello, World!'
ciphertext = cipher.encrypt(plaintext)

# Decrypt the message
decrypted = cipher.decrypt(ciphertext)
```

### Using Different Key Sizes

```python
# AES-128 (16-byte key)
cipher_128 = AES(b'0123456789abcdef', key_size=128)

# AES-192 (24-byte key)
cipher_192 = AES(b'0123456789abcdef01234567', key_size=192)

# AES-256 (32-byte key)
cipher_256 = AES(b'0123456789abcdef0123456789abcdef', key_size=256)
```

### Block Encryption

```python
# Encrypt a single 16-byte block
block = b'ExactlySixteenBB'
ciphertext_block = cipher.encrypt_block(block)
plaintext_block = cipher.decrypt_block(ciphertext_block)
```

### Without Padding

```python
# For data that's already a multiple of 16 bytes
plaintext = b'Exactly16BytesXX'
ciphertext = cipher.encrypt(plaintext, padding=False)
decrypted = cipher.decrypt(ciphertext, padding=False)
```

### With Logging

```python
import logging
from aesfs import AES, setup_logger

# Set up logger with desired level
setup_logger("aesfs", level=logging.INFO)

# Enable logging when creating cipher
cipher = AES(key=b'This is a key123', key_size=128, enable_logging=True)

# Encryption operations will now be logged
ciphertext = cipher.encrypt(b'Hello, World!')
# Output: INFO - AES cipher initialized with 128-bit key (10 rounds)
#         INFO - Starting encryption of 13 bytes
#         INFO - Encryption complete: 16 bytes
```

For detailed round-by-round logging, use `logging.DEBUG` level.

### Diffie-Hellman Key Exchange

```python
from aesfs import DiffieHellman, AES

# Alice generates her keys
alice = DiffieHellman()
alice.generate_private_key()
alice_public = alice.generate_public_key()

# Bob generates his keys
bob = DiffieHellman()
bob.generate_private_key()
bob_public = bob.generate_public_key()

# They exchange public keys and compute shared secret
alice_shared = alice.compute_shared_secret(bob_public)
bob_shared = bob.compute_shared_secret(alice_public)

# Both have the same shared secret!
assert alice_shared == bob_shared

# Derive an AES key from the shared secret
aes_key = alice.get_shared_secret_bytes(32)  # 256-bit key
cipher = AES(aes_key, key_size=256)

# Now Alice and Bob can communicate securely
message = b'Secret message'
ciphertext = cipher.encrypt(message)
decrypted = cipher.decrypt(ciphertext)
```

## Running Tests

```bash
python -m unittest discover tests
```

## Examples

See the `examples/` directory for more usage examples:

```bash
python examples/basic_usage.py
python examples/logging_example.py
python examples/diffie_hellman_example.py
```

## Design Principles

### High Cohesion

Each module has a single, focused responsibility:
- Constants module only contains lookup tables
- Galois Field module only handles GF(2^8) arithmetic
- Transformations module only implements the four AES transformations
- Key expansion module only handles key scheduling
- Diffie-Hellman module only implements key exchange protocol
- AES module only orchestrates the encryption/decryption process

### Low Coupling

Modules depend only on what they need:
- Constants module has no dependencies
- Galois Field module has no dependencies
- Diffie-Hellman module has no dependencies on other aesfs modules
- Transformations depend only on constants and Galois Field
- Key expansion depends only on constants
- AES module orchestrates but doesn't implement low-level details

## Security Notice

This is an educational implementation. For production use, please use established cryptographic libraries like `cryptography` or `pycryptodome`.

## License

MIT License - see LICENSE file for details.
