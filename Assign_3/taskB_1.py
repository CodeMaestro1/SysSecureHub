import logging
import logging.config
import os
from taskA_1 import  FILE_SIZE
from taskA_2_create_test_files import create_files
from taskA_2 import generate_hashes_for_files, compare_hashes_with_database, read_database_hashes

logging.config.fileConfig(fname='mylogger.conf', disable_existing_loggers = False)

# Get the logger specified in the file
logger = logging.getLogger(__name__)

fake_malicious_string = {r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"}

def create_directory_with_files(path, max_depth, dirs_per_dir=2, files_per_dir=3, depth=0, dir_num=1):
    # end cond
    if depth == max_depth:
        return 
    
    current_dir = os.path.join(path, f"dir_{dir_num}_level_{depth}")
    os.makedirs(current_dir, exist_ok=True)

    # random files in current dir    
    for i in range(files_per_dir):
        filename = f"dir_{dir_num}_level_{depth}_file_{i}"
        file_path = os.path.join(current_dir, filename)
        create_files(1, FILE_SIZE, fake_malicious_string, file_path, True)
    
    # rec fill the rest
    for i in range(dirs_per_dir):
        create_directory_with_files(current_dir, max_depth, files_per_dir, depth=depth+1, dir_num=i+1)

def log_malware_data(malware_info_list):
    """Logs all collected malware data to the configured logger."""
    for malware_info in malware_info_list:
        # Extract details from each entry in the list
        file_name = malware_info.get("name", "Unknown")
        md5_hash = malware_info.get("md5", "Unknown")
        sha256_hash = malware_info.get("sha256", "Unknown")
        malware_type = malware_info.get("type", "Unknown")
        time_stamp = malware_info.get("time_stamp", "Unknown")

        # Format the log message
        log_message = (
            f"File: {file_name} | MD5: {md5_hash} | SHA256: {sha256_hash} | "
            f"Type: {malware_type} | Timestamp: {time_stamp}"
        )

        # Log the message
        logger.info(log_message)


if __name__ == "__main__":
    path = f'{os.getcwd()}/taskB_1_files'
    database_path = '/home/codemaestro/Desktop/SysSecureHub/Assign_3/malware_signature.txt'

    create_directory_with_files(path, max_depth=2, dirs_per_dir=2, files_per_dir=3)

    database_hashes = read_database_hashes(database_path)
    all_collected_data = []

    for root, dirs, files in os.walk(path):
        file_hashes = generate_hashes_for_files(root)
        collected_data = compare_hashes_with_database(file_hashes, database_hashes)
        if collected_data:
            all_collected_data.extend(collected_data)
    
    if all_collected_data:
        log_malware_data(all_collected_data)
            
