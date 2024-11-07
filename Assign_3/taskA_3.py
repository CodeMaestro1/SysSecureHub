import numpy as np
from tabulate import tabulate
import hashlib
import os
from taskA_2 import calculate_file_hash


folderpath = 'Assign_3/sample_pdfs-20241104T090609Z-001/sample_pdfs'
sha_algorithms = ["sha1", "sha256","sha512"]

def calculate_hashes_for_pdf(folderpath):
    hashes = {}
    for file in os.listdir(folderpath):
        hashes[file] = {}
        for selected_algorithm in sha_algorithms:
            file_hash = calculate_file_hash(f'{folderpath}/{file}', selected_algorithm)
            hashes[file][selected_algorithm] = file_hash
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



hashes = calculate_hashes_for_pdf(folderpath)
tables, hash_funcs, files = pairwise_compare_hashes(hashes)
print_tables(tables, hash_funcs, files)