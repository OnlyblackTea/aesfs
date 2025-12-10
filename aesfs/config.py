"""
Configuration Management Module

This module provides configuration management for AES encryption parameters.
It supports loading configuration from YAML, JSON, or Python dictionaries,
with fallback to sensible defaults.

High cohesion: Contains only configuration loading and validation logic.
Low coupling: Minimal dependencies, uses only standard library.
"""

import json
import os
from typing import Dict, Any, Optional


# Default configuration values
DEFAULT_CONFIG = {
    "key_size": 128,
    "padding": True,
    "enable_logging": False,
    "logging_level": "INFO",
}


class AESConfig:
    """
    Configuration class for AES encryption parameters.

    This class manages AES encryption settings, providing a clean interface
    for loading configuration from various sources while maintaining defaults.

    Attributes:
        key_size (int): AES key size in bits (128, 192, or 256)
        padding (bool): Whether to use PKCS7 padding
        enable_logging (bool): Whether to enable logging
        logging_level (str): Logging level (DEBUG, INFO, WARNING, ERROR)
    """

    def __init__(self, config_dict: Optional[Dict[str, Any]] = None):
        """
        Initialize AES configuration.

        Args:
            config_dict: Optional dictionary with configuration values.
                        If None, uses default configuration.

        Raises:
            ValueError: If configuration values are invalid
        """
        # Start with defaults
        config = DEFAULT_CONFIG.copy()

        # Override with provided values
        if config_dict:
            config.update(config_dict)

        # Validate and set attributes
        self.key_size = self._validate_key_size(config.get("key_size"))
        self.padding = bool(config.get("padding", True))
        self.enable_logging = bool(config.get("enable_logging", False))
        self.logging_level = self._validate_logging_level(
            config.get("logging_level", "INFO")
        )

    def _validate_key_size(self, key_size: int) -> int:
        """
        Validate key size parameter.

        Args:
            key_size: Key size in bits

        Returns:
            Validated key size

        Raises:
            ValueError: If key size is not 128, 192, or 256
        """
        if key_size not in (128, 192, 256):
            raise ValueError(
                f"Invalid key_size: {key_size}. " f"Must be 128, 192, or 256 bits"
            )
        return key_size

    def _validate_logging_level(self, level: str) -> str:
        """
        Validate logging level parameter.

        Args:
            level: Logging level string

        Returns:
            Validated logging level (uppercase)

        Raises:
            ValueError: If logging level is invalid
        """
        valid_levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
        level_upper = level.upper()
        if level_upper not in valid_levels:
            raise ValueError(
                f"Invalid logging_level: {level}. " f"Must be one of {valid_levels}"
            )
        return level_upper

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.

        Returns:
            Dictionary representation of configuration
        """
        return {
            "key_size": self.key_size,
            "padding": self.padding,
            "enable_logging": self.enable_logging,
            "logging_level": self.logging_level,
        }

    @classmethod
    def from_json_file(cls, filepath: str) -> "AESConfig":
        """
        Load configuration from JSON file.

        Args:
            filepath: Path to JSON configuration file

        Returns:
            AESConfig instance

        Raises:
            FileNotFoundError: If file doesn't exist
            json.JSONDecodeError: If file is not valid JSON
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Configuration file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            config_dict = json.load(f)

        return cls(config_dict)

    @classmethod
    def from_yaml_file(cls, filepath: str) -> "AESConfig":
        """
        Load configuration from YAML file.

        Note: Requires PyYAML to be installed. Falls back to JSON parsing
        if PyYAML is not available.

        Args:
            filepath: Path to YAML configuration file

        Returns:
            AESConfig instance

        Raises:
            FileNotFoundError: If file doesn't exist
            ImportError: If PyYAML is not installed and file is YAML
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Configuration file not found: {filepath}")

        try:
            import yaml

            with open(filepath, "r", encoding="utf-8") as f:
                config_dict = yaml.safe_load(f)
        except ImportError:
            # Fall back to trying JSON if YAML not available
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    config_dict = json.load(f)
            except json.JSONDecodeError:
                raise ImportError(
                    "PyYAML is required to load YAML files. "
                    "Install it with: pip install pyyaml"
                )

        return cls(config_dict)

    @classmethod
    def from_file(cls, filepath: str) -> "AESConfig":
        """
        Load configuration from file (auto-detect format).

        Supports .json, .yaml, and .yml file extensions.

        Args:
            filepath: Path to configuration file

        Returns:
            AESConfig instance

        Raises:
            ValueError: If file extension is not supported
        """
        ext = os.path.splitext(filepath)[1].lower()

        if ext == ".json":
            return cls.from_json_file(filepath)
        elif ext in (".yaml", ".yml"):
            return cls.from_yaml_file(filepath)
        else:
            raise ValueError(
                f"Unsupported configuration file format: {ext}. "
                f"Supported formats: .json, .yaml, .yml"
            )


def load_config(config_source: Optional[Any] = None) -> AESConfig:
    """
    Load AES configuration from various sources.

    This is a convenience function that can load configuration from:
    - None (uses defaults)
    - Dictionary
    - File path (string)
    - AESConfig instance (returns as-is)

    Args:
        config_source: Configuration source (None, dict, str path, or AESConfig)

    Returns:
        AESConfig instance

    Raises:
        TypeError: If config_source type is not supported
    """
    if config_source is None:
        return AESConfig()
    elif isinstance(config_source, AESConfig):
        return config_source
    elif isinstance(config_source, dict):
        return AESConfig(config_source)
    elif isinstance(config_source, str):
        return AESConfig.from_file(config_source)
    else:
        raise TypeError(
            f"Invalid config_source type: {type(config_source)}. "
            f"Expected None, dict, str, or AESConfig"
        )
