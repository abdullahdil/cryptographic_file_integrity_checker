
# merkle.py
import hashlib
import math

def hash_pair(left, right, algo='sha256'):
    h = hashlib.new(algo)
    h.update((left + right).encode())
    return h.hexdigest()

def build_merkle_tree(file_hashes: dict, algo='sha256'):
    """
    Given a dict of file_path: hash, build a Merkle Tree and return the root hash.
    Returns (merkle_root, tree_structure)
    """
    if not file_hashes:
        return None, []

    # Step 1: Prepare leaf nodes (sorted for consistency)
    leaves = [h for _, h in sorted(file_hashes.items())]

    # Step 2: If odd number of leaves, duplicate last (to make pairs)
    def _next_level(nodes):
        if len(nodes) % 2 != 0:
            nodes.append(nodes[-1])
        return [hash_pair(nodes[i], nodes[i+1], algo) for i in range(0, len(nodes), 2)]

    tree_levels = [leaves]
    current = leaves

    while len(current) > 1:
        current = _next_level(current)
        tree_levels.append(current)

    merkle_root = current[0]
    return merkle_root, tree_levels
