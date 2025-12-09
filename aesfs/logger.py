"""
Logging Module for AESFS

This module provides logging functionality for the AES implementation.
High cohesion: Contains only logging configuration and utilities.
Low coupling: No dependencies on other AESFS modules.
"""

import logging
from typing import Optional


def setup_logger(name: str = "aesfs", level: int = logging.WARNING) -> logging.Logger:
    """
    Set up and return a logger for AESFS.
    
    Args:
        name: Logger name (default: "aesfs")
        level: Logging level (default: logging.WARNING)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Only configure if not already configured
    if not logger.handlers:
        logger.setLevel(level)
        
        # Create console handler
        handler = logging.StreamHandler()
        handler.setLevel(level)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(handler)
    
    return logger


def get_logger(name: str = "aesfs") -> logging.Logger:
    """
    Get an existing logger or create a new one.
    
    Args:
        name: Logger name (default: "aesfs")
    
    Returns:
        Logger instance
    """
    return logging.getLogger(name)
