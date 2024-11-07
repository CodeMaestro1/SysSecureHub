from pip._vendor import requests
import os
from taskA_1 import  FILE_SIZE
from taskA_2_create_test_files import create_files
from taskA_2 import search_directory_for_malware_files

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
        create_files(1, FILE_SIZE, fake_malicious_string, file_path)
    
    # rec fill the rest
    for i in range(dirs_per_dir):
        create_directory_with_files(current_dir, max_depth, files_per_dir, depth=depth+1, dir_num=i+1)

if __name__ == "__main__":
    path = f'{os.getcwd()}/taskB_1_files'
    database_path = 'malware_signature.txt'

    create_directory_with_files(path, max_depth=2, dirs_per_dir=2, files_per_dir=3)

    malware_files = search_directory_for_malware_files(path, database_path)

    # scan_directory(path, database_path)