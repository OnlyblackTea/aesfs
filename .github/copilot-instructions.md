# Copilot Instructions for aesfs

## Repository Overview
This repository is **aesfs** - an AES (Advanced Encryption Standard) filesystem project. The project focuses on implementing cryptographic filesystem operations using AES encryption.

## Project Context
- **Purpose**: Reproduce and implement AES filesystem functionality
- **License**: MIT License (Copyright 2025 Quanzhou Li)
- **Language**: To be determined based on implementation

## Coding Standards

### General Guidelines
- Write clear, maintainable, and well-documented code
- Follow security best practices, especially for cryptographic operations
- Ensure all cryptographic implementations follow industry standards
- Add comprehensive error handling for all operations

### Security Considerations
- Never hardcode encryption keys or sensitive data
- Use secure random number generators for key generation
- Implement proper key management and storage practices
- Validate all inputs to prevent security vulnerabilities
- Follow OWASP guidelines for cryptographic storage

### Documentation
- Add clear docstrings/comments for all public functions and classes
- Document encryption algorithms and parameters used
- Provide usage examples for key operations
- Maintain up-to-date README with setup and usage instructions

### Testing
- Write unit tests for all cryptographic functions
- Include integration tests for filesystem operations
- Test edge cases and error conditions
- Ensure tests cover security-critical code paths

### Code Review
- All code changes should be reviewed for security implications
- Verify cryptographic implementations against standards
- Check for potential vulnerabilities before merging

## Development Workflow
1. Create feature branches from main branch
2. Write tests before implementing features (TDD when possible)
3. Ensure all tests pass before submitting pull requests
4. Keep commits focused and atomic
5. Write descriptive commit messages

## Questions to Consider
When working on this repository, always consider:
- Is this cryptographic implementation secure?
- Are we following AES best practices?
- Is the filesystem interface intuitive and safe (proper access controls, secure file permissions, encrypted data at rest)?
- Are error messages helpful without exposing sensitive information?
- Is the code performance-efficient for filesystem operations?
