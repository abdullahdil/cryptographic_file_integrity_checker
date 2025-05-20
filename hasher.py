
# hasher.py
import hashlib
import os

def compute_file_hash(filepath, algo="sha256"):
    """Compute hash of a single file using specified algorithm."""
    h = hashlib.new(algo)
    
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(4096):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        print(f"[ERROR] Failed to hash {filepath}: {e}")
        return None

def hash_all_files_in_directory(directory, algo="sha256"):
    """Scan directory and return dict of file paths to hashes."""
    hash_map = {}
    for root, dirs, files in os.walk(directory):
        for name in files:
            filepath = os.path.join(root, name)
            file_hash = compute_file_hash(filepath, algo)
            if file_hash:
                hash_map[filepath] = file_hash
    return hash_map
