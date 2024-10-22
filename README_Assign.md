## Overview

This project implements two cryptographic algorithms: Elliptic Curve Diffie-Hellman (ECDH) and RSA. These are widely used for secure key exchange and encryption, respectively.

## Elliptic Curve Diffie-Hellman (ECDH) Algorithm

### Features

- **Key Pair Generation**: Supports generating key pairs, either using a provided private key or generating one automatically.
- **Secure Shared Secret Derivation**: Safely computes a shared secret between two parties using their public-private key pairs.
- **Command-Line Interface (CLI)**: A user-friendly interface for seamless interaction with the algorithm.

### Prerequisites

Ensure the following dependencies are installed:

- **GCC** (GNU Compiler Collection)
- **libsodium** (for cryptographic functions)
- **GMP Library** (for large integer operations)

### Compilation and Execution

To compile the ECDH program, run the following command in the project directory:

```bash
make ecdh_assign_1
```

This will automatically compile the code using the provided Makefile. Please ensure that the `libsodium` library is properly installed, as it’s dynamically linked during compilation.

## RSA Algorithm

This project also includes an implementation of the RSA algorithm for encryption and decryption.

### Features

- **RSA Key-Pair Generation**: Allows key-pair generation based on a specified key length.
- **Encryption**: Encrypts input data and stores the encrypted output.
- **Decryption**: Decrypts encrypted input and stores the decrypted output.
- **Performance Comparison**: Compares the performance of RSA encryption and decryption processes.

### Compilation and Execution

To compile the RSA program, use the following command:

```bash
make rsa_assign_1
```

This will generate the RSA executable. The GMP library is required for handling the large integers used in RSA operations.

## Assumptions

- The program assumes safe memory management, and no additional safety measures (e.g., memory wiping) are implemented. For this reason, we did not use helper functions from the libsodium library for memory handling in either program.
- It is assumed that all necessary libraries (libsodium, GMP) are properly installed and correctly linked during the compilation process.

## References

- [RSA algorithm in C using the GMP library](https://gist.github.com/akosma/865b887f993de462369a04f4e81596b8)
- [RSA using gmp](https://gist.github.com/aishraj/4010562)
- [C++ Generate a random prime using GMP library](https://stackoverflow.com/questions/56412315/c-generate-a-random-prime-using-gmp-library)
- [Generating Random Primes](https://crypto.stackexchange.com/questions/2532/generating-random-primes)
- [How do computers choose the RSA value for e?](https://www.reddit.com/r/crypto/comments/6363di/how_do_computers_choose_the_rsa_value_for_e/)
