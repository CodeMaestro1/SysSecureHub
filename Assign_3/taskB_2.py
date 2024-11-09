import os
import shutil

from config import QUARANTINE_PATH

def quarantine_files(file_entries):
    for fentry in file_entries:
        quarantine_file(fentry["name"], fentry["fpath"], fentry["sha256"])

def quarantine_file(filename, fpath, sha256):
    """Quarantines a file by moving it to a new directory and renaming it.

    Args:
        filename (str): The name of the file 
        fpath (str): The path to the file
        sha256 (str): the sha256 hash of the file

    Returns:
        bool: returns True if the file was successfully quarantined, False otherwise
    """
    # how to deal with duplicate name_hash (?)
    new_name = f"{filename}_{sha256}"
    quarantined_fpath = os.path.join(QUARANTINE_PATH, new_name)
    os.makedirs(quarantined_fpath, exist_ok=True)

    try:
        shutil.move(fpath, quarantined_fpath)
        print(f"Quarantined: {fpath} to {quarantined_fpath}")
    except PermissionError:
        print(f"Permission denied when trying to quarantine: {fpath}")
        return False  # Failure
    except FileNotFoundError:
        print(f"File not found: {fpath}")
        return False  # Failure
    except Exception as e:
        print(f"Couldn't quarantine: {fpath}: {e}")
        return False # failure
    
    return True # success 

