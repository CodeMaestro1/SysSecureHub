import os
import argparse

#Define some tags to search for
TAG = ("Virus", "spyware", "ransomware", "trojan", "exploit")

FILE_SIZE = 50 # 50 bytes

NORMAL_FILE_TAG = "Non-Malware"

FAKE_MALICIOUS_STRINGS = [
    "This is a fake malicious string 1",
    "This is a fake malicious string 2",
    "This is a fake malicious string 3",
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
]

FAKE_MALICIOUS_STRING = [r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"]

# Make sure your API key is set in the environment
API_ABUSE = os.getenv("API_ABUSE")

HYBRID_ANALYSIS = os.getenv("HYBRID_ANALYSIS")

#####Configurations for taskA_2_create_test_files.py

OUTPUT_DIR = r"./test_files" # Output directory for test files

TEST_FILES_COUNT = 15


#####Configurations for taskA_2.py
HASH_ALGORITHMS = {'md5', 'sha256', 'sha1', 'sha512'}


#####Configurations for taskA_3.py
SHA_ALGORITHMS = ["sha1", "sha256", "sha512"]

FOLDER_PATH = r'sample_pdfs-20241104T090609Z-001/sample_pdfs/'

#####Configurations for taskB_2.py
QUARANTINE_PATH = 'taskB_2_quarantined_files'

#####Configurations for taskC_1.py
SEARCH_DIR = 'taskB_1_files'
SIGNATURE_FILE = 'malware_signature.txt'

