import hashlib
import os


def sha256sum(filename):
    with open(filename, 'rb', buffering=65536) as f:
        hash = hashlib.file_digest(f, 'sha256').hexdigest()
        print("SHA-256 done!")
        return hash


def sha512sum(filename):
    with open(filename, 'rb', buffering=65536) as f:
        hash = hashlib.file_digest(f, 'sha512').hexdigest()
        print("SHA-512 done!")
        return hash


def sha384sum(filename):
    with open(filename, 'rb', buffering=65536) as f:
        hash = hashlib.file_digest(f, 'sha384').hexdigest()
        print("SHA-384 done!")
        return hash


def sha224sum(filename):
    with open(filename, 'rb', buffering=65536) as f:
        hash = hashlib.file_digest(f, 'sha224').hexdigest()
        print("SHA-224 done!")
        return hash


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

    print("Hashing...")
    if not os.path.isfile(file_path):
        print(f"The file {file_path} does not exist.")
        return

    file_name = os.path.basename(file_path)
    base_name, _ = os.path.splitext(file_name)
    output_file = f"{base_name}-hashes.txt"

    hashes = {'SHA-224': sha224sum(file_path),
              'SHA-256': sha256sum(file_path),
              'SHA-384': sha384sum(file_path),
              'SHA-512': sha512sum(file_path)}

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
    current_hashes = {
        'SHA-224': sha224sum(file_path),
        'SHA-256': sha256sum(file_path),
        'SHA-384': sha384sum(file_path),
        'SHA-512': sha512sum(file_path),
    }

    print("Verifying hashes...")
    for hash_type, current_hash in current_hashes.items():
        if hash_type in stored_hashes:
            if stored_hashes[hash_type] == current_hash:
                print(f"{hash_type} valid: {current_hash}")
            else:
                print(f"{hash_type} invalid! Expected: {stored_hashes[hash_type]}, Got: {current_hash}",
                      "File may have been modified!")
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
