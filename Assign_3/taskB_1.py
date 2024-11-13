import logging
import logging.config
import os

from config import  FILE_SIZE, fake_malicious_string
from taskA_2_create_test_files import create_files
from taskA_2 import generate_hashes_for_files, compare_hashes_with_database, read_database_hashes
from taskB_2 import quarantine_files


logging.config.fileConfig(fname='mylogger.conf', disable_existing_loggers = False)

# Get the logger specified in the file
logger = logging.getLogger(__name__)

def create_directory_with_files(path, max_depth, dirs_per_dir=2, files_per_dir=3, depth=0, dir_num=1):
    # end cond
    if depth == max_depth:
        return 
    
    current_dir = os.path.join(path, f"L{depth}D{dir_num}")
    os.makedirs(current_dir, exist_ok=True)

    # this contains a file loop in itself 
    create_files(files_per_dir-len(fake_malicious_string), FILE_SIZE, fake_malicious_string, current_dir, True)
    
    # rec fill the rest
    for i in range(dirs_per_dir):
        create_directory_with_files(current_dir, max_depth, dirs_per_dir=dirs_per_dir, 
                                    files_per_dir=files_per_dir, depth=depth+1, dir_num=i+1)

def log_malware_data(malware_info_list):
    """Logs all collected malware data to the configured logger."""
    for malware_info in malware_info_list:
        # Extract details from each entry in the list
        file_name = malware_info.get("name", "Unknown")
        md5_hash = malware_info.get("md5", "Unknown")
        sha256_hash = malware_info.get("sha256", "Unknown")
        malware_type = malware_info.get("type", "Unknown")
        malware_level = malware_info.get("level", "Unknown")
        time_stamp = malware_info.get("time_stamp", "Unknown")
        file_size = malware_info.get("size", "Unknown")

        # Format the log message
        log_message = (
            f"File: {file_name} | MD5: {md5_hash} | SHA256: {sha256_hash} | "
            f"Type: {malware_type} | Level: {malware_level} | Size: {file_size} | Timestamp: {time_stamp}"
        )

        # Log the message
        logger.info(log_message)

def search_folder_recursive(path, database_hashes):
    all_collected_data = []

    # search current dir (skipped in loop)
    file_hashes = generate_hashes_for_files(path)
    collected_data = compare_hashes_with_database(file_hashes, database_hashes)
    if collected_data:
        all_collected_data.extend(collected_data)

    # recursive search 
    for root, dirs, _ in os.walk(path):
        for dir in dirs:
            cur_path = os.path.join(root, dir)
            file_hashes = generate_hashes_for_files(cur_path)
            collected_data = compare_hashes_with_database(file_hashes, database_hashes)
            if collected_data:
                all_collected_data.extend(collected_data)

    return all_collected_data

def taskB_packaged(path, database_path):
    database_hashes = read_database_hashes(database_path) # wasteful but wtvr

    all_collected_data = search_folder_recursive(path, database_hashes)

    if all_collected_data:
        log_malware_data(all_collected_data)

        quarantine_files(all_collected_data, database_path)


if __name__ == "__main__":
    path = f'taskB_1_files'
    database_path = 'malware_signature.txt'

    create_directory_with_files(path, max_depth=3, dirs_per_dir=3, files_per_dir=3)

    database_hashes = read_database_hashes(database_path)

    all_collected_data = search_folder_recursive(path, database_hashes)

    if all_collected_data:
        log_malware_data(all_collected_data)

        # on if we consider b as a whole task like c 
        quarantine_files(all_collected_data, database_path)

            