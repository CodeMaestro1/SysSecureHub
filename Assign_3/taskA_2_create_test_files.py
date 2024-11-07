import os
from taskA_1 import get_rand_string

# Directory where the files will be stored
OUTPUT_DIR = r"test_files"
TEST_FILES_COUNT = 15

fake_malicious_strings = [
    "This_is_a_malicious_file_1",
    "This_is_a_malicious_file_2",
    "This_is_a_malicious_file_3",
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
]

""" Creates 'malware'/'normal' files and returns their required metadata in a dict """
def create_files(files_num, file_length):
    """Creates files with random strings and fake malicious strings.

    Args:
        files_num (_type_): _description_
        file_length (_type_): _description_
    """
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        print(f"Creating files in: {os.path.abspath(OUTPUT_DIR)}")  # Added print statement
    except OSError as e:
        print(f"Error creating directory '{OUTPUT_DIR}': {e}")
        return

    # Create normal files
    for i in range(files_num - len(fake_malicious_strings)):
        with open(f"{OUTPUT_DIR}/{i}.txt", "w") as f:
            f.write(get_rand_string(file_length))

    # Create malicious files
    for i, malicious_string in enumerate(fake_malicious_strings, start=files_num - len(fake_malicious_strings)):
        with open(f"{OUTPUT_DIR}/{i}.txt", "w") as f:
            f.write(malicious_string)


if __name__ == "__main__":
    create_files(TEST_FILES_COUNT, 50)
    print(f"Files created in '{OUTPUT_DIR}' directory.")