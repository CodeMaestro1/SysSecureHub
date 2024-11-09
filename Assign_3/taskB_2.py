import os
import shutil

QUARANTINE_PATH = 'taskB_2_quarantined_files'

def quarantine_files(file_entries):
    for fentry in file_entries:
        quarantine_file(fentry["name"], fentry["fpath"], fentry["sha256"])

def quarantine_file(filename, fpath, sha256):
    # how to deal with duplicate name_hash (?)
    new_name = f"{filename}_{sha256}"
    quarantined_fpath = os.path.join(QUARANTINE_PATH, new_name)
    os.makedirs(quarantined_fpath, exist_ok=True)

    # print("here" + quarantined_fpath)

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

