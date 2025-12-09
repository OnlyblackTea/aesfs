"""Setup script for AESFS package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="aesfs",
    version="0.1.0",
    author="Quanzhou Li",
    description="A simple AES implementation with high cohesion and low coupling",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/OnlyblackTea/aesfs",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.7",
    test_suite="tests",
)
