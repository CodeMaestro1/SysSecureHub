from pip._vendor import requests
import os
import hashlib
import datetime
import string
import random
from config import TAG, FILE_SIZE, NORMAL_FILE_TAG , FAKE_MALICIOUS_STRINGS , API_ABUSE, HYBRID_ANALYSIS


def get_rand_string(length):
    """Generates a random string of specified length.

    Args:
        length (int): The length of the random string to generate.

    Returns:
        string: A random string of the specified length.
    """
    random_string = ''.join(random.choices(string.ascii_letters + string.digits,k=length)) # initializing size of string
    return random_string

def generate_sha256_md5(random_string):
    """Generates a SHA256 and MD5 hash for a given random string.

    Args:
        random_string (str): a string generated using a random function

    Returns:
        tuple: A tuple containing the SHA256 and MD5 hashes.
    """
    sha256 = hashlib.sha256(random_string.encode()).hexdigest()
    md5 = hashlib.md5(random_string.encode()).hexdigest()

    return sha256, md5

def generate_non_malicious_data(number):
    """Generates non-malicious data.

    Args:
        number (int): The number of non-malicious data to generate.

    Returns:
        list: A list of non-malicious data.
    """
    non_malicious_data = []
    for _ in range(number):
        random_string = get_rand_string(FILE_SIZE)
        sha256, md5 = generate_sha256_md5(random_string)
        non_malicious_data.append({
            "sha256_hash": sha256,
            "md5_hash": md5,
            "tag": NORMAL_FILE_TAG,
            "first_seen": datetime.datetime.now().strftime("%Y-%m-%d"),
            "severity_level": "Safe"
        })
    return non_malicious_data


def get_malware_samples_by_tag(tag, limit=5):
    url = "https://mb-api.abuse.ch/api/v1/"
    
    headers = {
        "API-KEY": API_ABUSE 
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

def get_threat_level(sha256):
    api_base_url = f"https://www.hybrid-analysis.com/api/v2/search/hash"

    API_KEY = HYBRID_ANALYSIS

    headers = {
        "accept":"application/json",
        "Content-Type":"application/x-www-form-urlencoded",
        "api-key": API_KEY
    }

    payload = { "hash": sha256 }

    response = requests.post(api_base_url, headers=headers, data=payload)

    if response.status_code == 200:
        data = response.json()
        return data[0].get("threat_level")
    elif response.status_code == 403:
        print("Error fetching threat level: 403 Forbidden. Check your API key and permissions.")
        return None
    else:
        print(f"Error fetching threat level: {response.status_code}")
        return None

def classify_threat_level(threat_level):
    """Given a threat level, return a severity level.

    Args:
        threat_level (int): The threat level to classify.

    Returns:
        dict: The severity level of the threat, otherwise "Unknown".
    """
    threat_level_map = {1: "Low", 2: "Medium", 3: "High"}
    return threat_level_map.get(threat_level, "Unknown")


def write_malware_signature_file(file, malware_samples, tag):
    """Writes malware samples to the provided file in the specified format format.

    Args:
        file (file object): a file object where data will be written.
        malware_samples (list): a list of dictionaries containing malware samples.
        tag (string): the tag associated with the data (e.g., "Virus").
    """
    if malware_samples:
        for sample in malware_samples:
            # Extract the required fields
            md5_hash = sample.get("md5_hash", "N/A")
            sha256_hash = sample.get("sha256_hash", "N/A")
            tag = tag
            first_seen = sample.get("first_seen").split(" ")[0]  # Extract the date only
            threat_level = get_threat_level(sha256_hash)
            severity_level = classify_threat_level(threat_level)
            
            # Format each entry
            entry_line = f"{md5_hash} | {sha256_hash} | {tag} | {first_seen} | {severity_level}\n"
            
            file.write(entry_line)
    else:
        file.write("No results found.\n")

def write_non_malware_signature_file(file, non_malicious_data):
    """
    Writes non-malicious data entries to the provided file in a structured format.

    Args:
        file (file object): The file object where data will be written.
        non_malicious_data (list): A list of dictionaries containing non-malicious data.
        tag (str): The tag associated with the data (e.g., "Non-Malware").
    """
    if non_malicious_data:
        for sample in non_malicious_data:
            # Extract the required fields with default values
            md5_hash = sample.get("md5_hash", "N/A")
            sha256_hash = sample.get("sha256_hash", "N/A")
            tag = sample.get("tag", "N/A")
            first_seen = sample.get("first_seen", "N/A")
            severity_level = sample.get("severity_level", "N/A")
            
            # Format each entry line
            entry_line = f"{md5_hash} | {sha256_hash} | {tag} | {first_seen} | {severity_level}\n"
            
            # Write the formatted line to the file
            file.write(entry_line)
    else:
        file.write("No results found.\n")

def write_fake_malicious_data(file, list_string):
    """ Writes fake malicious data entries to the provided file in a specific format.

    Args:
        file (file object): A file object where data will be written.
        list_string (list): A list with the "malicious" strings to be written.
    """
    for string in list_string:
        sha256, md5 = generate_sha256_md5(string)
        tag = "Fake Malware"
        first_seen = datetime.datetime.now().strftime("%Y-%m-%d")
        severity_level = "High"
        
        entry_line = f"{md5} | {sha256} | {tag} | {first_seen} | {severity_level}\n"
        
        file.write(entry_line)


if __name__ == "__main__":
    # Open the file once in write mode to write headers
    with open("malware_signature.txt", "w") as file:
        # Write header only once
        file.write("MD5 Hash    |   SHA256 Hash   | Malware Type    |   Infection Date  |   Severity Level\n")
        file.write("-----------------------------------------------------------------------------------------------------------\n")
        
        # Iterate over each tag and write corresponding entries
        for tag in TAG:
            malware_samples = get_malware_samples_by_tag(tag)
            write_malware_signature_file(file, malware_samples, tag)

        non_malicious_data = generate_non_malicious_data(21)
        write_non_malware_signature_file(file, non_malicious_data)
        write_fake_malicious_data(file, FAKE_MALICIOUS_STRINGS)