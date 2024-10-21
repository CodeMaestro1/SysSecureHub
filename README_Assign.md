## Overview

This project implements the Elliptic Curve Diffie-Hellman (ECDH) algorithm ans the  RSA algorithm 

## ECDH Algorithm

## Features

- **Key Pair Generation**: Generate key pairs with or without provided private keys.
- **Secure Shared Secret Generation**: Safely derive a shared secret between parties.
- **Command-Line Interface**: User-friendly CLI for easy interaction.

## Prerequisites

Ensure you have the following installed:

- GCC (GNU Compiler Collection)
- libsodium
- Make

## Compilation and Execution

To compile the program, a Makefile is provided. Simply run:

```bash
make ecdh_assign_1
```

This command will handle the compilation process automatically. Please ensure that the `libsodium` library is installed, as the linking process is dynamic.

The program supports all necessary options and is designed with memory safety in mind. Thus, specific memory safety features have not been explicitly utilized.

## RSA Algorithm Implementation

This project also includes an implementation of the RSA algorithm. To compile the RSA program, use the same Makefile with the following command:

```bash
make rsa_assign_1
```

The executable will be generated upon successful compilation. The GMP library is utilized for RSA functionality.

## Assumptions

- The program is designed with security in mind and has been tested for memory safety.
- The necessary libraries are assumed to be correctly installed and linked.

## References

[Add any references or resources related to ECDH, RSA, or libraries used.]
