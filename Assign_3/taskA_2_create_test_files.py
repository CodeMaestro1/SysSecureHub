import os
from taskA_1 import get_rand_string

# Directory where the files will be stored
OUTPUT_DIR = r"./test_files"
TEST_FILES_COUNT = 15

fake_malicious_strings = [
    "This_is_a_malicious_file_1",
    "This_is_a_malicious_file_2",
    "This_is_a_malicious_file_3",
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
]


def create_files(num_non_malicious_files, file_length, fake_malicious_strings=fake_malicious_strings, output_dir_par=OUTPUT_DIR):
    """Creates files with random strings and fake malicious strings.

    Args:
        num_non_malicious_files (int): Number of non-malicious files to create.
        file_length (int): Length of each file.
        fake_malicious_strings (list): List of malicious strings.
        output_dir_par (str): Output directory path.
    """
    try:
        os.makedirs(output_dir_par, exist_ok=True)
        print(f"Creating files in: {os.path.abspath(output_dir_par)}")  # Added print statement
    except OSError as e:
        print(f"Error creating directory '{output_dir_par}': {e}")
        return
    
    if num_non_malicious_files > 0 and len(fake_malicious_strings) > 0: 
        # Create normal files
        for i in range(num_non_malicious_files):
            with open(f"{output_dir_par}/{i}.txt", "wb") as file:
                file.write(get_rand_string(file_length).encode('utf-8'))

        # Create malicious files
        for i, malicious_string in enumerate(fake_malicious_strings, start=num_non_malicious_files):
            with open(f"{output_dir_par}/{i}.txt", "wb") as file:
                file.write(malicious_string.encode('utf-8'))
    else:
        print("Number of files to create should be greater than 0.")
        return

if __name__ == "__main__":
    create_files(TEST_FILES_COUNT, 50)
    print(f"Files created in '{OUTPUT_DIR}' directory.")