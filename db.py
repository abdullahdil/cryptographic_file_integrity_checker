import sqlite3
from config import DB_FILE

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Create file_hashes table with additional columns
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_hashes (
            file_path TEXT PRIMARY KEY,
            hash TEXT NOT NULL,
            algorithm TEXT,
            status TEXT,
            last_checked DATETIME,
            version INTEGER
        )
    ''')
    # Create merkle_root table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS merkle_root (
            id INTEGER PRIMARY KEY,
            root TEXT NOT NULL,
            timestamp DATETIME
        )
    ''')
    # Create tamper_log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tamper_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT,
            old_root TEXT,
            new_root TEXT,
            timestamp DATETIME
        )
    ''')
    conn.commit()
    conn.close()

def store_hashes(file_hashes):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    for file_path, hash_value in file_hashes.items():
        cursor.execute('''
            INSERT OR REPLACE INTO file_hashes (file_path, hash, algorithm, status, last_checked, version)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (file_path, hash_value, "sha256", "valid", None, 1))
    conn.commit()
    conn.close()

def store_merkle_root(root):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO merkle_root (id, root, timestamp) VALUES (1, ?, CURRENT_TIMESTAMP)', (root,))
    conn.commit()
    conn.close()

def add_tamper_event(file_path, old_root, new_root):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO tamper_log (file_path, old_root, new_root, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)', (file_path, old_root, new_root))
    conn.commit()
    conn.close()