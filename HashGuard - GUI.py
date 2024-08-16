import hashlib
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD

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

def create_hashes(file_path):
    if not os.path.isfile(file_path):
        messagebox.showerror("Error", f"The file {file_path} does not exist.")
        return

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
                messagebox.showerror("Error", f"Error calculating hash for {algo}: {e}")

    write_hashes_to_file(output_file, hashes)
    messagebox.showinfo("Success", f"Hashes have been written to {output_file}")

def verify_integrity(file_path, hashes_file):
    if not os.path.isfile(file_path) or not os.path.isfile(hashes_file):
        messagebox.showerror("Error", "One or both of the files do not exist.")
        return

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
                messagebox.showerror("Error", f"Error calculating hash for {algo}: {e}")

    mismatch_found = False
    results = []
    for hash_type, current_hash in current_hashes.items():
        if hash_type in stored_hashes:
            if stored_hashes[hash_type] != current_hash:
                results.append(f"{hash_type} invalid!")
                mismatch_found = True
        else:
            results.append(f"{hash_type} not found in hashes file.")
            mismatch_found = True

    if mismatch_found:
        messagebox.showerror("Verification Results", "\n".join(results))
    else:
        messagebox.showinfo("Verification Results", "All hashes are valid.")

def browse_file(entry):
    file_path = filedialog.askopenfilename(title="Select File", filetypes=[("All Files", "*.*")])
    if file_path:
        entry.delete(0, tk.END)
        entry.insert(0, file_path)

def process_file():
    file_path = file_path_entry.get()
    if not os.path.isfile(file_path):
        messagebox.showerror("Error", "File does not exist.")
        return

    if verify_mode.get():
        hashes_file = filedialog.askopenfilename(title="Select Hashes File", filetypes=[("Text Files", "*.txt")])
        if hashes_file:
            verify_integrity(file_path, hashes_file)
    else:
        create_hashes(file_path)

def toggle_mode():
    verify_mode.set(not verify_mode.get())
    mode_button.config(text="Verify Mode" if not verify_mode.get() else "Hash Mode")

def drop(event):
    file_path = event.data
    if os.path.isfile(file_path):
        file_path_entry.delete(0, tk.END)
        file_path_entry.insert(0, file_path)

root = TkinterDnD.Tk()
root.title("HashGuard")
root.geometry("1280x960")
root.configure(bg='black')

verify_mode = tk.BooleanVar(value=False)

tk.Label(root, text="File Path:", bg="black", fg="white").pack(pady=5)
file_path_entry = tk.Entry(root, width=60)
file_path_entry.pack(pady=5)

browse_button = tk.Button(root, text="Browse", command=lambda: browse_file(file_path_entry), bg="white", fg="black")
browse_button.pack(pady=5)

tk.Label(root, text="Drag and Drop or Browse to select a file", bg="black", fg="white").pack(pady=10)

mode_button = tk.Button(root, text="Verify Mode", command=toggle_mode, bg="white", fg="black")
mode_button.pack(pady=5)

process_button = tk.Button(root, text="Process File", command=process_file, bg="white", fg="black")
process_button.pack(pady=5)

root.drop_target_register(DND_FILES)
root.dnd_bind('<<Drop>>', drop)

root.mainloop()