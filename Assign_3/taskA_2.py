import os
import hashlib

NORMAL_FILE_TAG = "Normal_File"

""" generates a hash for a file based on provided hash func """
def hash_file(fpath, hash_func):
    hash = hash_func()

    with open(fpath, "rb") as f:
        while True:
            chunk = f.read(4096)  # read in chunks of 4k
            if not chunk:
                break
            hash.update(chunk)

    return hash.hexdigest()

""" searches hash in database """
def search_hash_in_database(sha256, database_path):
    # iter through file lines
    line_num = 0
    with open(database_path, 'r') as db:
        for line in db:
            if line_num > 1: # skip headers 
                # get items in line
                items = [col.strip() for col in line.split('|')]
                
                if items[1] == sha256:
                    return items
            line_num += 1
    return None

""" scan a folder non recursively """
def scan_folder_non_rec(folder_path, database_path):
    # iter through filenames in files folder 
    for filename in os.listdir(folder_path):
        fpath = os.path.join(folder_path, filename) # get filepath 
        
        if os.path.isfile(fpath):
            sha256 = hash_file(fpath, hashlib.sha256)  
            items = search_hash_in_database(sha256, database_path) 

            # detected in database
            if items != None:
                malware_type = items[2]
                if malware_type != NORMAL_FILE_TAG:
                    severity_level = items[4]
                    print(f"File {filename} was flagges as malware of type={malware_type}, severity_level={severity_level}")

folder_path = 'files'
database_path = 'my_malware_samples.txt'
scan_folder_non_rec(folder_path, database_path)
    