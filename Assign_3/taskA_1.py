from pip._vendor import requests
import os
from datetime import datetime

#Define some tags to search for
TAG = ("Virus", "spyware", "Ransomware", "trojan", "exploit")

def get_malware_samples_by_tag(tag, limit=5):
    url = "https://mb-api.abuse.ch/api/v1/"
    
    headers = {
        "API-KEY": os.getenv("API_ABUSE")  # Make sure your API key is set in the environment
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

    API_KEY = os.getenv("HYBRID_ANALYSIS")

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
    threat_level_map = {1: "Low", 2: "Medium", 3: "High"}
    return threat_level_map.get(threat_level, "Unknown")


def write_file(file, malware_samples, tag):
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


if __name__ == "__main__":
    # Open the file once in write mode to write headers
    with open("malware_signature.txt", "w") as file:
        # Write header only once
        file.write("MD5 Hash    |   SHA256 Hash   | Malware Type    |   Infection Date  |   Severity Level\n")
        file.write("-----------------------------------------------------------------------------------------------------------\n")
        
        # Iterate over each tag and write corresponding entries
        for tag in TAG:
            malware_samples = get_malware_samples_by_tag(tag)
            write_file(file, malware_samples, tag)


