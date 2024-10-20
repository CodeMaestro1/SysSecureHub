# Compiler and flags
CC=gcc
CFLAGS=-I.

# Target executable
TARGET=main

# Source files
SRCS=$(wildcard *.c)

# Object files
OBJS=$(SRCS:.c=.o)

# Rule to build the executable
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS)

# Rule to build object files
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

# Rule to compile and execute ecdh_assign_1 with user-specified arguments # run it like: make run_ecdh ARGS="-o ecdh.txt -a 5 -b 2"
.PHONY: run_ecdh
run_ecdh: $(TARGET)
	./$(TARGET) $(ARGS)

# Clean rule
.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJS)