import os
import shutil

from config import QUARANTINE_PATH
from taskA_2 import read_database_hashes

def quarantine_files(file_entries, database_path):
    dhashes = read_database_hashes(database_path)

    for fentry in file_entries:
        quarantine_success = quarantine_file(fentry["name"], fentry["fpath"])
        if quarantine_success:
            severity_level = dhashes[fentry["md5"]]["severity_level"]
            # print(severity_level)
            print(f"Quarantined: {fentry['fpath']} of level {severity_level}")

def quarantine_file(filename, fpath):
    """Quarantines a file by moving it to a new directory and renaming it.

    Args:
        filename (str): The name of the file 
        fpath (str): The path to the file
        sha256 (str): the sha256 hash of the file

    Returns:
        bool: returns True if the file was successfully quarantined, False otherwise
    """
    new_dir_name = f"{filename}"
    quarantined_fpath = os.path.join(QUARANTINE_PATH, new_dir_name)

    # check if file is already quarantined and change name 
    quarantined_fpath_with_file = os.path.join(quarantined_fpath, filename)
    change, new_file_name = new_name_if_exists(quarantined_fpath_with_file)
    if change:
        # get dir from fpath
        cur_dir = os.path.dirname(fpath)
    
        # calc the new path
        new_fpath = os.path.join(cur_dir, new_file_name)
        # rename the file 
        os.rename(fpath, new_fpath)
        # new fpath (with new name)
        fpath = new_fpath

    os.makedirs(quarantined_fpath, exist_ok=True)

    try:
        shutil.move(fpath, quarantined_fpath)
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

def new_name_if_exists(fpath):
    if os.path.exists(fpath):
        # get name and type 
        cur_dir, file_name = os.path.split(fpath)
        text, type = os.path.splitext(file_name)
        
        counter = 1
        # add counter to fname
        new_name = f"{text}_{counter}{type}"
        new_fpath = os.path.join(cur_dir, new_name)
        
        # repeat until name+counter doesnt exist 
        while os.path.exists(new_fpath):
            counter += 1
            new_name = f"{text}_{counter}{type}"
            new_fpath = os.path.join(cur_dir, new_name)
        
        return True, new_name
    # normal case - doesn't exist
    else:
        return False, ""
    