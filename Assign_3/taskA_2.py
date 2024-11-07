import hashlib
import os

hash_algorithms = {'md5', 'sha256', 'sha1', 'sha512'}

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

def generate_hashes_for_files(current_directory):
    """Generates hashes for the specified files in the given folder.

    Args:
        current_directory (str): The path to the folder containing the files.

    Returns:
        dict: A dictionary where each key is a filename and the value is a dictionary of algorithm-hash pairs.
    """
    hashes = {}
    
    for path, _, files in os.walk(current_directory):
        for filename in files:
            file_path = os.path.join(path, filename)
            hashes[filename] = {}
            for algorithm in hash_algorithms:
                file_hash = calculate_file_hash(file_path, algorithm)
                hashes[filename][algorithm] = file_hash
    
    return hashes

def compare_hashes_with_database(hashes, hashes_database):
    """Compares file hashes with the database and prints matches.
    
    Args:
        hashes (dict): A dictionary where each key is a filename and the value is a dictionary of algorithm-hash pairs.
        hashes_database (dict): A dictionary where each key is a hash value and the value contains malware details.
    """
    for filename, hash_dict in hashes.items():
        for algorithm, file_hash in hash_dict.items():
            details = hashes_database.get(file_hash)
            if details:
                malware_type = details.get('malware_type')
                print(f"File '{filename}' has a matching {algorithm.upper()} hash '{file_hash}' in the database. Malware Type: {malware_type}")


def read_database_hashes(database_file):
    with open(database_file, 'r') as file:
        database_hashes = {}

        for line in file:
            if line.startswith('-') or line.startswith('MD5 Hash'):
                continue
            else:
                # Strip leading whitespace from the line
                stripped_line = line.strip()
                
                # Split the stripped line by '|' and strip any extra whitespace
                columns = [col.strip() for col in stripped_line.split('|')]
                
                if len(columns) < 3:
                    continue  # Skip incomplete lines
                
                # Extract the first three columns
                md5_hash, sha256_hash, malware_type = columns[:3]
                
                # Store in the dictionary
                database_hashes[md5_hash] = {
                    "sha256_hash": sha256_hash,
                    "malware_type": malware_type
                }
    
    return database_hashes

if __name__ == '__main__':
    current_directory = os.getcwd()
    for path, folders, files in os.walk(current_directory, topdown=True):
        # Remove 'sample_pdfs' from folders to skip traversing it
        if 'sample_pdfs' in folders:
            folders.remove('sample_pdfs')

        for folder in folders:
            hashes = generate_hashes_for_files(os.path.join(path, folder))
            
            database_hashes = read_database_hashes('malware_signature.txt')
            compare_hashes_with_database(hashes, database_hashes)
    
