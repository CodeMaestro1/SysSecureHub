import os
import random 

from taskA_1 import get_rand_string
from config import OUTPUT_DIR, TEST_FILES_COUNT, FAKE_MALICIOUS_STRINGS, FILE_SIZE


def create_files(num_non_malicious_files, file_length, fake_malicious_strings=FAKE_MALICIOUS_STRINGS, output_dir_par=OUTPUT_DIR, use_dir_in_name=False):
    """Creates files with random strings and fake malicious strings.

    Args:
        num_non_malicious_files (int): Number of non-malicious files to create.
        file_length (int): Length of each file.
        fake_malicious_strings (list): List of malicious strings.
        output_dir_par (str): Output directory path.
        use_dir_in_name (bool): Flag to include directory name in filenames.
    """
    try:
        os.makedirs(output_dir_par, exist_ok=True)
        print(f"Creating files in: {os.path.abspath(output_dir_par)}")
    except OSError as e:
        print(f"Error creating directory '{output_dir_par}': {e}")
        return

    if num_non_malicious_files > 0 and len(fake_malicious_strings) > 0:
        base_name = f"{os.path.basename(os.path.normpath(output_dir_par))}_rand_{random.randint(1, 10000)}" if use_dir_in_name else "" # rand identifier to showcase log entries are unique (level 2 and above has identical file names)
        
        # Create non-malicious files
        try:
            for i in range(num_non_malicious_files):
                file_name = f"{base_name}_{i}.txt" if use_dir_in_name else f"{i}.txt"
                with open(os.path.join(output_dir_par, file_name), "wb") as file:
                    file.write(get_rand_string(file_length).encode('utf-8'))

            # Create malicious files
            for i, malicious_string in enumerate(fake_malicious_strings, start=num_non_malicious_files):
                file_name = f"{base_name}_{i}.txt" if use_dir_in_name else f"{i}.txt"
                with open(os.path.join(output_dir_par, file_name), "wb") as file:
                    file.write(malicious_string.encode('utf-8'))
        except OSError as e:
            print(f"Error creating file: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        else:
            print("Files created successfully.")
        finally:
            if num_non_malicious_files <= 0:
                print("Number of files to create should be greater than 0.")
    else:
        print("Number of files to create should be greater than 0.")

if __name__ == "__main__":
    create_files(TEST_FILES_COUNT, FILE_SIZE)
    print(f"Files created in '{OUTPUT_DIR}' directory.")