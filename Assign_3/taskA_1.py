import os
import random 
import hashlib
from datetime import datetime
import requests

# tags & filetypes
TAGS = ['Worm', 'Ransomware', 'Virus', 'Spyware']
FILETYPES = ['exe', 'jar', 'sh']
# normal file tag
NORMAL_FILE_TAG = "Normal_File"

# files malware/normal types
MALWARE_TYPE = 1
NORMAL_TYPE = 0

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

""" generates the database, combining data from the api and the user provided 'malware' files """
def generate_database(output_file, api_count, my_files_samples=[]):
    api_malware_samples = []
    tag_count = int(api_count/len(TAGS))

    for tag in TAGS:
        # get samples for tag
        cur_api_malware_samples = get_malware_samples_by_tag(tag, limit=tag_count)

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

        malware_samples = api_malware_samples + my_files_samples # concat lists 
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
            severity_level = classify_threat_score(get_threat_score(sha256)) # for my malware return Unknown

            entry = [md5, sha256, type, infection_date, severity_level]
            file.write(f'{" | ".join(entry)}\n')
    
    print("Database created")

""" creates 'malware'/'normal' files and returns their required metadata in a dict """
def create_files(files_count, type, file_length=50):
    os.makedirs('files', exist_ok=True)
    
    my_files_samples = []
    for i in range(files_count):
        # cur sample 
        sample = {}

        # get file type
        filetype = get_filetype(i) # pseudo-random choice

        # get file name 
        if type == MALWARE_TYPE: fpath = f'files/mfile_{i}.{filetype}'
        else: fpath = f'files/file_{i}.{filetype}'
        
        # write some random info 
        with open(fpath, 'w') as file:
            file.write(get_rand_bytes(file_length))
        
        # put info into sample 
        sample["md5_hash"] = hash_file(fpath, hashlib.md5) # hashlib.md5().hexdigest()
        sample["sha256_hash"] = hash_file(fpath, hashlib.sha256) # hashlib.sha256().hexdigest()
        if type == MALWARE_TYPE: sample["classified_tag"] = random.choice(TAGS) 
        else: sample["classified_tag"] = NORMAL_FILE_TAG
        sample["first_seen"] = datetime(2001, 9, 11).strftime("%Y-%m-%d") # random date

        my_files_samples.append(sample)

    if type==MALWARE_TYPE: name_type = 'malware'
    else: name_type = 'normal'
    print(f"Created {files_count} {name_type} files.")

    return my_files_samples

""" return hashes for some files """
def generate_hashes(folderpath, filenames):
    hashes = {}
    for filename in filenames:
        fpath = f'{os.getcwd()}/{folderpath}/{filename}'

        md5 = hash_file(fpath, hashlib.md5)
        sha256 = hash_file(fpath, hashlib.sha256)
        sha512 = hash_file(fpath, hashlib.sha512)

        hashes[filename] = {}
        hashes[filename]["md5"] = md5
        hashes[filename]["sha256"] = sha256
        hashes[filename]["sha512"] = sha512
        # print(f'\n{filename}:\nmd5: {md5}\nsha256: {sha256}\nsha512: {sha512}')
    
    return hashes

""" run (1) """
my_normal_samples = create_files(25, type=NORMAL_TYPE)
my_malware_samples = create_files(25, type=MALWARE_TYPE)

my_files_samples = my_normal_samples + my_malware_samples
generate_database('my_malware_samples.txt', 25, my_files_samples=my_files_samples)
