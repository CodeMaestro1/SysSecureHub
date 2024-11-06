from pip._vendor import requests
import json
import os
import argparse

parser = argparse.ArgumentParser(description='Query sample information by tag on Malware Bazaar by abuse.ch')
parser.add_argument('-t', '--tag', help='Type of malware to search for (e.g. Worm, Ransomware)', type=str, metavar="TAG", required=True)

args = parser.parse_args()

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

def get_threat_score(sha256):
    api_base_url = f"https://www.hybrid-analysis.com/api/v2/"

    API_KEY = os.getenv("HYBRID_ANALYSIS")
    print(os.getenv("API_ABUSE"))

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

def classify_threat_score(threat_score):
    if threat_score is None:
        return "Unknown"
    elif threat_score < 30:
        return "Low"
    elif threat_score < 70:
        return "Medium"
    else:
        return "High"

# Retrieve samples and include all desired fields
malware_samples = get_malware_samples_by_tag(args.tag)

# Write results to a file
with open("malware_signature.txt", "w") as file:
    file.write("MD5 Hash    |   SHA256 Hash   |  Malware Type |   Infection Date    | Severity Level\n")
    file.write("-------------------------------------------------------------------------------------------------------------\n")
    if malware_samples:
        for sample in malware_samples:
            # Extract the required fields

            sha256_hash = str(sample.get("sha256_hash"))
            threat_score = get_threat_score(sha256_hash)
            severity_level = classify_threat_score(threat_score)

            entry = {
                "sha256_hash": sha256_hash,
                "md5_hash": sample.get("md5_hash"),
                "first_seen": sample.get("first_seen"),
                "tag": args.tag,
                "severity_level": severity_level
            }

            file.write(json.dumps(entry) + "\n")
    else:
        file.write("No results found.\n")

print("Results written to malware_signature.txt")


