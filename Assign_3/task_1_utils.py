import os 
import random
import requests
import numpy as np
from tabulate import tabulate

LEVELS = ['Low', 'Medium', 'High', 'Critical']
FILETYPES = ['exe', 'jar', 'sh']

""" Get recent samples from API """
def get_recent_malware_samples(limit):
    url = "https://mb-api.abuse.ch/api/v1/"

    headers = {
        "API-KEY": os.getenv("API_ABUSE")
    }

    payload = {
        "query": "get_recent",
        "selector": str(limit) # for some reason only works with 100 weird (?)
    }

    response = requests.post(url, headers=headers, data=payload)
    
    if response.status_code == 200:
        data = response.json()
        if data.get("query_status") == "ok":
            samples = data.get("data", [])
            return samples
        else:
            print(f"Query failed: {data.get('query_status')}")
            return []
    else:
        print(f"Error fetching samples: {response.status_code}")
        return []

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

""" generates rand string of some chars """
def get_rand_bytes(length):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    random_string = ''.join(random.choice(chars) for _ in range(length))
    return random_string

""" function that determines severity level (isn't specified) """
def calculate_severity_level():    
    return random.choice(LEVELS)

""" pick filetype for file creation """
def get_filetype(i):
    # pseudo-random to overide the old files 
    return FILETYPES[i%len(FILETYPES)]

""" pairwise compare hashes """
def pairwise_compare_hashes(hashes):
    files = list(hashes.keys())
    hash_funcs = list(hashes[files[0]].keys())

    tables = np.zeros((len(files), len(files), len(hash_funcs)), dtype=int)

    for i in range(len(files)):
        for j in range(i, len(files)):
            for k, hash_func in enumerate(hash_funcs):
                if hashes[files[i]][hash_func] == hashes[files[j]][hash_func]:
                    tables[i][j][k] = 1
                    tables[j][i][k] = 1
                else:
                    tables[i][j][k] = 0
                    tables[j][i][k] = 0
    
    print_tables(tables, hash_funcs, files)

def print_tables(tables, hash_funcs, files): 
    for k, hash_func in enumerate(hash_funcs):
        print(f"\nPairwise comparison for {hash_func} hash function:")

        print(tabulate(tables[:, :, k].tolist(), headers=files, tablefmt="orgtbl"))