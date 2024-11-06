import os
import random 
import hashlib
from datetime import datetime
import argparse

import task_1_utils as t1u

TAGS = ['Worm', 'Ransomware', 'Virus', 'Spyware']

""" generates the database, combining data from the api and the user provided 'malware' files """
def generate_database(output_file, api_count, my_malware_samples=[]):
    api_malware_samples = []
    tag_count = int(api_count/len(TAGS))

    for tag in TAGS:
        # get samples for tag
        cur_api_malware_samples = t1u.get_malware_samples_by_tag(tag, limit=tag_count)

        # add tag (of interest) to current samples (for later)
        for sample in cur_api_malware_samples:
            sample["classified_tag"] = tag 

        if cur_api_malware_samples != []: 
            api_malware_samples += cur_api_malware_samples
            print(f"Got {tag} malware samples from API")
        else: 
            print(f"Error getting {tag} samples from API")


    with open(output_file, 'w') as file:
        file.write("MD5 Hash | SHA256 Hash | Malware Type | Infection Date | Severity Level\n")
        file.write(f'{"-"*85}\n')

        malware_samples = api_malware_samples + my_malware_samples # concat lists 
        rand_order = list(range(len(malware_samples))) 
        random.shuffle(rand_order) # get a random order because 

        for r in rand_order:
            # cur sample
            sample = malware_samples[r]

            # get required info
            md5 = sample["md5_hash"]
            sha256 = sample["sha256_hash"]
            type = sample["classified_tag"]
            infection_date = sample["first_seen"].split(" ")[0] # get only date
            severity_level = t1u.classify_threat_score(t1u.get_threat_score(sha256)) # for my malware return Unknown

            entry = [md5, sha256, type, infection_date, severity_level]
            file.write(f'{" | ".join(entry)}\n')
    
    print("Database created")

""" creates random 'normal' files """
def create_normal_files(normal_count, file_length=50):
    os.makedirs('files', exist_ok=True)
    my_normal_files = [f'files/file_{i}.{t1u.get_filetype(i)}' for i in range(normal_count)] # pseudo-random choice

    # create files and add some random bytes (to get different hashes)
    for fpath in my_normal_files:
        with open(fpath, 'w') as file:
            file.write(t1u.get_rand_bytes(file_length))

    print("Created normal files.")

""" creates 'malware' files and returns their required metadata in a dict """
def create_malware_files(malware_count, file_length=50):
    os.makedirs('files', exist_ok=True)
    
    my_malware_samples = []
    for i in range(malware_count):
        sample = {}

        filetype = t1u.get_filetype(i) # pseudo-random choice

        fpath = f'files/mfile_{i}.{filetype}'
        with open(fpath, 'w') as file:
            file.write(t1u.get_rand_bytes(file_length))
        
        sample["md5_hash"] = t1u.hash_file(fpath, hashlib.md5) # hashlib.md5().hexdigest()
        sample["sha256_hash"] = t1u.hash_file(fpath, hashlib.sha256) # hashlib.sha256().hexdigest()
        sample["classified_tag"] = random.choice(TAGS) 
        sample["first_seen"] = datetime(2001, 9, 11).strftime("%Y-%m-%d") # random date

        my_malware_samples.append(sample)

    print("Created malware files.")

    return my_malware_samples

""" return hashes for some files """
def generate_hashes(folderpath, filenames):
    hashes = {}
    for filename in filenames:
        fpath = f'{os.getcwd()}/{folderpath}/{filename}'

        md5 = t1u.hash_file(fpath, hashlib.md5)
        sha256 = t1u.hash_file(fpath, hashlib.sha256)
        sha512 = t1u.hash_file(fpath, hashlib.sha512)

        hashes[filename] = {}
        hashes[filename]["md5"] = md5
        hashes[filename]["sha256"] = sha256
        hashes[filename]["sha512"] = sha512
        # print(f'\n{filename}:\nmd5: {md5}\nsha256: {sha256}\nsha512: {sha512}')
    
    return hashes

# """ parser """
# parser = argparse.ArgumentParser(description='Query sample information by tag on Malware Bazaar by abuse.ch')
# parser.add_argument('-t', '--tag', help='Type of malware to search for (e.g. Worm, Ransomware)', type=str, metavar="TAG", required=True)

# args = parser.parse_args()

""" run (1) """
create_normal_files(3)
my_malware_samples = create_malware_files(5)

generate_database('my_malware_samples.txt', 12, my_malware_samples=my_malware_samples)

""" run (2) """
# Here it should search files dir and look classify the files inside as malicious or not (should be easy but its 0330)

""" run (3) """
folderpath = 'assignment3_all/sample_pdfs-20241104T090609Z-001/sample_pdfs'
filenames = [f'{i}.pdf' for i in [1, 2, 3, 4, 5, 8, 9, 10]]

hashes = generate_hashes(folderpath, filenames)
tables, hash_funcs, files = t1u.pairwise_compare_hashes(hashes)
t1u.print_tables(tables, hash_funcs, files)
