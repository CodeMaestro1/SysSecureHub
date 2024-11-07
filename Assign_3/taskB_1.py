from pip._vendor import requests
import os
import hashlib
import datetime
import string
import random

from taskA_2 import search_dir_recursive
from taskB_2 import quarantine_files

# import taskA_2 as tA2

#Define some tags to search for
TAG = ("Virus", "Spyware", "Ransomware", "Trojan", "Exploit")

FILE_SIZE = 50 # 50 bytes

fake_malicious_strings = [
    "This_is_a_malicious_file_1",
    "This_is_a_malicious_file_2",
    "This_is_a_malicious_file_3",
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
]

""" generates rand string of some chars """
def get_rand_string(length):
    """Generates a random string of specified length.

    Args:
        length (int): _description_

    Returns:
        _type_: _description_
    """
    random_string = ''.join(random.choices(string.ascii_letters + string.digits,k=length)) # initializing size of string
    return random_string

def fill_file(file_path):
    type = random.choice(["normal", "malware"])
    with open(file_path, 'w') as f:
        if type == "malware":
            f.write(random.choice(fake_malicious_strings))
        else:
            f.write(get_rand_string(FILE_SIZE))

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
        fill_file(file_path) # random choose malware/normal
    
    # rec fill the rest
    for i in range(dirs_per_dir):
        create_directory_with_files(current_dir, max_depth, files_per_dir, depth=depth+1, dir_num=i+1)

if __name__ == "__main__":
    path = f'{os.getcwd()}/taskB_1_files'
    database_path = 'malware_signature.txt'

    create_directory_with_files(path, max_depth=2, dirs_per_dir=2, files_per_dir=3)

    malware_files = search_dir_recursive(path, database_path)

    quarantine_files(malware_files)

    # scan_directory(path, database_path)