import os 
import random
import requests
# from pip._vendor import requests # why (?)
import numpy as np
from tabulate import tabulate

FILETYPES = ['exe', 'jar', 'sh']

""" Get recent samples from API """
def get_malware_samples_by_tag(tag, limit=5):
    url = "https://mb-api.abuse.ch/api/v1/"
    
    headers = {
        "API-KEY": os.getenv("API_ABUSE")
    }

    data = {
        "tag": tag,  # Tag to search for
        "query": "get_taginfo",  # Use get_taginfo to search by tag
        "selector": str(limit)  # Limit to the latest 5 entries
    }

    response = requests.post(url, headers=headers, data=data)
    
    if response.status_code == 200:
        data = response.json()
        if data.get("query_status") == "ok":
            samples = data.get("data", [])
            return samples[:limit]
        else:
            print(f"Query failed: {data.get('query_status')}")
            return []
    else:
        print(f"Error fetching samples: {response.status_code}")
        return []
    
""" gets threat score for a sha256 hash """
def get_threat_score(sha256):
    api_base_url = f"https://www.hybrid-analysis.com/api/v2/"

    API_KEY = os.getenv("HYBRID_ANALYSIS")
    # print(f'hererehrhehrehrherhe{API_KEY}')
    # print(os.getenv("API_ABUSE"))

    term = "search/hash"

    feeds_url = "feed/latest"

    user_agent = "Falcon Sandbox"

    headers = {
        "accept":"application/json",
        "Content-Type":"application/x-www-form-urlencoded",
        "User-Agent":user_agent,
        "api-key": API_KEY
    }

    data = { "hash": sha256 }

    response = requests.post(api_base_url + term, headers=headers, data=data)

    if response.status_code == 200:
        data = response.json()
        if isinstance(data, list) and len(data) > 0:
            return data[0].get("threat_score")
        else:
            print("Unexpected response format")
            return None
    elif response.status_code == 403:
        print("Error fetching threat score: 403 Forbidden. Check your API key and permissions.")
        return None
    else:
        print(f"Error fetching threat score: {response.status_code}")
        return None

""" classifirs threat score """
def classify_threat_score(threat_score):
    if threat_score is None:
        return "Unknown"
    elif threat_score < 30:
        return "Low"
    elif threat_score < 70:
        return "Medium"
    else:
        return "High"

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
    # maybe should be replaced with urandom as stated in the instructions 
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    random_string = ''.join(random.choice(chars) for _ in range(length))
    return random_string

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
    
    return tables, hash_funcs, files

def print_tables(tables, hash_funcs, files): 
    for k, hash_func in enumerate(hash_funcs):
        print(f"\nPairwise comparison for {hash_func} hash function:")

        print(tabulate(tables[:, :, k].tolist(), headers=files, tablefmt="orgtbl"))