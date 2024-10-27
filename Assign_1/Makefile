# Compiler and flags
CC=gcc
CFLAGS = -Wall -Wextra -g

# Define the source files and output files
ECDH_SRC = ecdh.c
ECDH_O = ecdh_assign_1
RSA_SRC = rsa.c
RSA_O = rsa_assign_1

# Define libraries to link against
ECDH_LIBS = -lsodium
RSA_LIBS = -lgmp

# Default option for make
all: $(ECDH_O) $(RSA_O)

# Rule to build ecdh_assign_1
$(ECDH_O): $(ECDH_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(ECDH_LIBS)

# Rule to build rsa_assign_1
$(RSA_O): $(RSA_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(RSA_LIBS)

# Clean rule
.PHONY: clean
clean:
	rm -f $(ECDH_O) $(RSA_O) *.o