import hashlib


def sha256sum(filename):
    with open(filename, 'rb', buffering=65536) as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def sha512sum(filename):
    with open(filename, 'rb', buffering=65536) as f:
        return hashlib.file_digest(f, 'sha512').hexdigest()


def sha384sum(filename):
    with open(filename, 'rb', buffering=65536) as f:
        return hashlib.file_digest(f, 'sha384').hexdigest()


def sha224sum(filename):
    with open(filename, 'rb', buffering=65536) as f:
        return hashlib.file_digest(f, 'sha224').hexdigest()


current_directory = str(input("Enter directory: "))
comparison = str(input("Enter hash to compare (skip if none): "))

print("SHA Hashing:- ")
if len(comparison) == 56:
    print("Compare: ", comparison)
print("SHA-224: ", sha224sum(current_directory))
if len(comparison) == 64:
    print("Compare: ", comparison)
print("SHA-256: ", sha256sum(current_directory))
if len(comparison) == 96:
    print("Compare: ", comparison)
print("SHA-384: ", sha384sum(current_directory))
if len(comparison) == 128:
    print("Compare: ", comparison)
print("SHA-512: ", sha512sum(current_directory))


