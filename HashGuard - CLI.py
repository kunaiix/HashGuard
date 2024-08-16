import hashlib
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

def calculate_hash(filename, algorithm):
    with open(filename, 'rb', buffering=65536) as f:
        hash = hashlib.new(algorithm)
        while chunk := f.read(65536):
            hash.update(chunk)

        if algorithm in ['shake_128', 'shake_256']:
            return algorithm.upper(), hash.hexdigest(512)
        else:
            return algorithm.upper(), hash.hexdigest()

def write_hashes_to_file(filename, hash_values):
    with open(filename, 'w') as f:
        for hash_type, hash_value in hash_values.items():
            f.write(f"{hash_type}: {hash_value}\n")

def read_hashes_from_file(filename):
    hashes = {}
    with open(filename, 'r') as f:
        for line in f:
            hash_type, hash_value = line.strip().split(': ', 1)
            hashes[hash_type] = hash_value
    return hashes

def create_hashes():
    file_path = str(input("Enter the file path: "))

    if not os.path.isfile(file_path):
        print(f"The file {file_path} does not exist.")
        return

    print("Hashing...")
    file_name = os.path.basename(file_path)
    base_name, _ = os.path.splitext(file_name)
    output_file = f"{base_name}-hashes.txt"

    hashes = {}
    algorithms = list(hashlib.algorithms_guaranteed)

    with ThreadPoolExecutor() as executor:
        future_to_algorithm = {executor.submit(calculate_hash, file_path, algo): algo for algo in algorithms}
        for future in as_completed(future_to_algorithm):
            algo = future_to_algorithm[future]
            try:
                hash_type, hash_value = future.result()
                hashes[hash_type] = hash_value
            except Exception as e:
                print(f"Error calculating hash for {algo}: {e}")

    write_hashes_to_file(output_file, hashes)
    print(f"Hashes have been written to {output_file}")

def verify_integrity():
    file_path = str(input("Enter the file path to verify: "))
    hashes_file = str(input("Enter the path to the hashes file: "))
    if not os.path.isfile(file_path) or not os.path.isfile(hashes_file):
        print("One or both of the files do not exist.")
        return

    print("Hashing...")
    stored_hashes = read_hashes_from_file(hashes_file)
    current_hashes = {}
    algorithms = list(hashlib.algorithms_guaranteed)

    with ThreadPoolExecutor() as executor:
        future_to_algorithm = {executor.submit(calculate_hash, file_path, algo): algo for algo in algorithms}
        for future in as_completed(future_to_algorithm):
            algo = future_to_algorithm[future]
            try:
                hash_type, hash_value = future.result()
                current_hashes[hash_type] = hash_value
            except Exception as e:
                print(f"Error calculating hash for {algo}: {e}")

    print("Verifying hashes...")
    for hash_type, current_hash in current_hashes.items():
        if hash_type in stored_hashes:
            if stored_hashes[hash_type] == current_hash:
                print(f"{hash_type} valid: {current_hash}")
            else:
                print(f"{hash_type} invalid! Expected: {stored_hashes[hash_type]}, Got: {current_hash}",
                      "File has been modified!")
        else:
            print(f"{hash_type} not found in hashes file.")

def menu():
    while True:
        print("\nSelect a task:")
        print("1. Hash a file")
        print("2. Verify file integrity")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            create_hashes()
        elif choice == '2':
            verify_integrity()
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    menu()
