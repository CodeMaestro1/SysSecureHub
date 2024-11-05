import requests
import json
import os

def get_recent_malware_samples(limit=50):
    url = "https://mb-api.abuse.ch/api/v1/"

    headers = {
        "API-KEY": os.getenv("API_ABUSE")  # Add your API key here
    }

    payload = {
        "query": "get_recent",
        "selector": str(limit)  # Limit can be 100 to get the latest samples
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

# Example usage
malware_samples = get_recent_malware_samples(limit=100)  # Change limit as needed
print(json.dumps(malware_samples, indent=4))  # Pretty print the results
