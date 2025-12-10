"""
Example: Using AES with configuration file.

This example demonstrates how to use the AES cipher with external configuration
files, allowing you to change encryption parameters without modifying code.
"""

from aesfs import AES
from aesfs.config import load_config


def example_json_config():
    """Example: Load configuration from JSON file."""
    print("=== Using JSON Configuration ===")

    # Load configuration from JSON file
    config = load_config("config.json")
    print(f"Loaded config: {config.to_dict()}")

    # Create AES cipher with configuration
    key = b"This is a key123"
    cipher = AES(key, config=config)

    # Encrypt and decrypt
    plaintext = b"Hello from JSON config!"
    ciphertext = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(ciphertext)

    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")
    print()


def example_yaml_config():
    """Example: Load configuration from YAML file."""
    print("=== Using YAML Configuration ===")

    try:
        # Load configuration from YAML file
        config = load_config("config.yaml")
        print(f"Loaded config: {config.to_dict()}")

        # Create AES cipher with configuration (256-bit key for config.yaml)
        key = b"0123456789abcdef0123456789abcdef"
        cipher = AES(key, config=config)

        # Encrypt and decrypt
        plaintext = b"Hello from YAML config!"
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)

        print(f"Plaintext:  {plaintext}")
        print(f"Decrypted:  {decrypted}")
        print()
    except ImportError as e:
        print(f"YAML example skipped: {e}")
        print("Install PyYAML to use YAML configs: pip install pyyaml")
        print()


def example_dict_config():
    """Example: Use configuration from dictionary."""
    print("=== Using Dictionary Configuration ===")

    # Create configuration from dictionary
    config_dict = {
        "key_size": 192,
        "padding": True,
        "enable_logging": True,
        "logging_level": "DEBUG",
    }
    config = load_config(config_dict)
    print(f"Config: {config.to_dict()}")

    # Create AES cipher with configuration
    key = b"192bit_key_24_bytes_!!!!"  # Exactly 24 bytes
    cipher = AES(key, config=config)

    # Encrypt and decrypt
    plaintext = b"Hello from dict config!"
    ciphertext = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(ciphertext)

    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")
    print()


def example_default_config():
    """Example: Use default configuration."""
    print("=== Using Default Configuration ===")

    # Create AES cipher with default configuration
    key = b"This is a key123"
    cipher = AES(key)  # Uses default config

    # Encrypt and decrypt
    plaintext = b"Hello with defaults!"
    ciphertext = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(ciphertext)

    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")
    print()


def main():
    """Run all configuration examples."""
    print("AESFS - Configuration File Examples\n")

    example_json_config()
    example_yaml_config()
    example_dict_config()
    example_default_config()

    print("All configuration examples completed!")


if __name__ == "__main__":
    main()
