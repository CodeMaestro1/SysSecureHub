# Overview

This project implements a custom logger alongside an Access Control Log Monitoring tool.

## Definition

A *malicious user* is defined as any user who attempts to modify a file without authorized access (i.e., lacking sufficient privileges).

## Access Control Logging Tool

### Logging Features

- Overrides `fopen` and `fwrite` functions using `LD_PRELOAD` to log access details.
- Maintains crucial logs including but not limited to user ID (UID), timestamp, access type, and additional relevant data.

## Access Control Log Monitoring Tool

### Monitoring Features

- Extracts incidents from the log file, identifying malicious users attempting unauthorized access to multiple files.
- Lists users who modified a specified file along with the count of modifications.
- Displays malicious users who attempted unauthorized access.

### Prerequisites

Ensure the following dependency is installed:

- **GCC** (GNU Compiler Collection)

### Compilation and Execution

To compile and run the program, use the following commands in the project directory:

```bash
make
make run
```

To delete all files created during testing (except for the log file), run:

```bash
make clean
```

If you also want to delete the log file, replace the following line in `make clean`:

```bash
find . -type f -name 'file_*' -not -name '*.log' -exec rm -f {} +
```

with:

```bash
rm -rf file_*
```

## References

- [getuid(2) — Linux manual page](https://man7.org/linux/man-pages/man2/getuid.2.html)
- [C File Exists](https://www.learnc.net/c-tutorial/c-file-exists/)
- [C library - strftime() function](https://www.tutorialspoint.com/c_standard_library/c_function_strftime.htm)
- [C library - gmtime() function](https://www.tutorialspoint.com/c_standard_library/c_function_gmtime.htm)
- [C Hashing Files With OpenSSL](https://blog.magnatox.com/posts/c_hashing_files_with_openssl/)
- [Use of fflush(stdin) in C](https://www.geeksforgeeks.org/use-fflushstdin-c/)