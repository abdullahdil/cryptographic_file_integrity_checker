# main.py

import config
from hasher import hash_all_files_in_directory
from merkle import build_merkle_tree
from db import init_db, store_hashes, store_merkle_root

def main():
    print("📁 Scanning folder:", config.MONITOR_DIR)

    # Step 1: Initialize DB
    init_db()

    # Step 2: Hash all files
    hashes = hash_all_files_in_directory(config.MONITOR_DIR)

    # Display hashes
    print("\n🧾 File Hashes:")
    for path, h in hashes.items():
        print(f"{path} => {h}")

    # Step 3: Build Merkle Tree
    merkle_root, tree = build_merkle_tree(hashes)

    print("\n🌲 Merkle Tree:")
    for i, level in enumerate(tree):
        print(f"Level {i}:")
        for node in level:
            print(f"  {node}")

    print(f"\n✅ Merkle Root: {merkle_root}")

    # Step 4: Store in DB
    store_hashes(hashes)
    store_merkle_root(merkle_root)

    print("\n📥 Stored hashes and Merkle root in file_hashes.db.")

if __name__ == "__main__":
    main()
