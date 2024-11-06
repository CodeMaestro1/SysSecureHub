import os
import hashlib
import random


# Constants
FILETYPES = ['exe', 'jar', 'sh']

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