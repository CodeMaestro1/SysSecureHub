import numpy as np
from tabulate import tabulate
import os
from taskA_2 import calculate_file_hash
from config import sha_algorithms , folderpath 


def calculate_hashes_for_pdf(folderpath):
    if not os.path.exists(folderpath):
        raise FileNotFoundError(f"The directory {folderpath} does not exist.")
    
    hashes = {}
    for file in os.listdir(folderpath):
        file_path = os.path.join(folderpath, file)
        if os.path.isfile(file_path):  # Ensure it's a file
            hashes[file] = {}
            for selected_algorithm in sha_algorithms:
                file_hash = calculate_file_hash(file_path, selected_algorithm)
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


if __name__ == "__main__":

    hashes = calculate_hashes_for_pdf(folderpath)
    tables, hash_funcs, files = pairwise_compare_hashes(hashes)
    print_tables(tables, hash_funcs, files)