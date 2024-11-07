import hashlib
import os 
import random
import string

NORMAL_FILE_TAG = "Non-Malware"

hash_algorithms = { 'sha1', 'sha256', 'sha512', 'md5' }

def calculate_file_hash(file_path, algorithm):
    """A general function to calculate the sha1, sha256, sha512, or md5 hash of a file.

    Args:
        file_path (_type_): _description_
        algorithm (_type_): _description_

    Returns:
        _type_: _description_
    """

    hash_func = hashlib.new(algorithm)

    with open(file_path, 'rb') as file:
        # Read the file in chunks of 4K bytes
        while chunk := file.read(4096):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

""" searches hash in database """
def search_hash_in_database(sha256, database_path):
    # iter through file lines
    line_num = 0
    keys = ['MD5 Hash', 'SHA256 Hash', 'Malware Type', 'Infection Date', 'Severity Level']
    with open(database_path, 'r') as db:
        for line in db:
            if line_num > 1: # skip headers 
                # get items in line
                items = [col.strip() for col in line.split('|')]
                entry = dict(zip(keys, items))
                
                if entry["SHA256 Hash"] == sha256:
                    return entry
            line_num += 1
    return None

""" scan a folder non recursively """
def scan_folder_non_rec(folder_path, database_path):
    malware_files_found = []
    # iter through filenames in files folder 
    for filename in os.listdir(folder_path):
        fpath = os.path.join(folder_path, filename) # get filepath 
        
        if os.path.isfile(fpath):
            sha256 = calculate_file_hash(fpath, 'sha256')  
            entry = search_hash_in_database(sha256, database_path) 
            # detected in database
            if entry != None:
                malware_type = entry["Malware Type"]
                # skip our normal files
                if malware_type != NORMAL_FILE_TAG:
                    # get threat
                    severity_level = entry["Severity Level"]
                    # get content (for testing)
                    with open(fpath, 'r') as f:
                        content = f.readlines()
                    print(f"File {filename} was flagges as malware of type={malware_type}, severity_level={severity_level}, contents={content}")
                    malware_files_found.append( {"name": filename, "fpath": fpath, "sha256": sha256} ) # add more info here if neede 

    return malware_files_found

if __name__ == '__main__':
    folder_path = 'test_files'
    database_path = 'malware_signature.txt'
    scan_folder_non_rec(folder_path, database_path)