import numpy as np
from tabulate import tabulate
import hashlib
import os


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
    
    return hashes

""" pairwise compare hashes """
def pairwise_compare_hashes(hashes):
    files = list(hashes.keys())
    hash_funcs = list(hashes[files[0]].keys())

    tables = np.zeros((len(files), len(files), len(hash_funcs)), dtype=int)

    for i in range(len(files)):
        for j in range(i, len(files)):
            for k, hash_func in enumerate(hash_funcs):
                if hashes[files[i]][hash_func] == hashes[files[j]][hash_func]:
                    tables[i][j][k] = 1
                    tables[j][i][k] = 1
                else:
                    tables[i][j][k] = 0
                    tables[j][i][k] = 0
    
    return tables, hash_funcs, files

def print_tables(tables, hash_funcs, files): 
    for k, hash_func in enumerate(hash_funcs):
        print(f"\nPairwise comparison for {hash_func} hash function:")

        print(tabulate(tables[:, :, k].tolist(), headers=files, tablefmt="orgtbl"))

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

folderpath = 'Assign_3/sample_pdfs-20241104T090609Z-001/sample_pdfs'
filenames = [f'{i}.pdf' for i in [1, 2, 3, 4, 5, 8, 9, 10]]

hashes = generate_hashes(folderpath, filenames)
tables, hash_funcs, files = pairwise_compare_hashes(hashes)
print_tables(tables, hash_funcs, files)