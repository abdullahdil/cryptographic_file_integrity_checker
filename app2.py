# file_integrity_monitor.py
# Consolidated script for file integrity monitoring with Flask dashboard, with fixed JavaScript syntax

import hashlib
import math
import sqlite3
import os
import csv
import time
import requests
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

app = Flask(__name__)

# --- Config Section ---
MONITOR_DIR = "./monitored_files"  # Directory to monitor
HASH_ALGO = "sha256"  # Default hash algorithm
DB_FILE = "file_hashes.db"  # SQLite database file
LOG_FILE = "logs/events.log"  # Log file (unused in this version)
WEBHOOK_URL = "https://discordapp.com/api/webhooks/1368958640425275504/5GWXcGW4vKBCVUmYSejXRFeRr-C3dWwaPhyF4EegwABFM37ge5EtWtqVa0WATy2j36u6"

# --- Database Functions ---
def init_db():
    """Creates the database and tables if they don't exist, and migrates schema if needed."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            # Create file_hashes table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_hashes (
                    file_path TEXT PRIMARY KEY,
                    hash TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    status TEXT NOT NULL,
                    last_checked TIMESTAMP,
                    version INTEGER DEFAULT 1
                )
            ''')
            # Migrate file_hashes: Add algorithm column if missing
            cursor.execute("PRAGMA table_info(file_hashes)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'algorithm' not in columns:
                cursor.execute('ALTER TABLE file_hashes ADD COLUMN algorithm TEXT NOT NULL DEFAULT "sha256"')
                print("Added 'algorithm' column to file_hashes table")

            # Create merkle_root table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS merkle_root (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    root TEXT NOT NULL,
                    timestamp TIMESTAMP
                )
            ''')
            # Migrate merkle_root: Add timestamp column if missing
            cursor.execute("PRAGMA table_info(merkle_root)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'timestamp' not in columns:
                cursor.execute('ALTER TABLE merkle_root ADD COLUMN timestamp TIMESTAMP')
                print("Added 'timestamp' column to merkle_root table")

            # Create tamper_log table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tamper_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT,
                    old_root TEXT,
                    new_root TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Create file_history table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT,
                    hash TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    change_type TEXT,
                    timestamp TIMESTAMP,
                    FOREIGN KEY (file_path) REFERENCES file_hashes (file_path)
                )
            ''')
            conn.commit()
        print(f"Database initialized at {DB_FILE}")
    except Exception as e:
        print(f"Error initializing database: {e}")

def store_hashes(file_hashes, algorithm):
    """Stores all file hashes into the database with status and version tracking."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            for path, hash_val in file_hashes.items():
                cursor.execute('SELECT hash, algorithm, version FROM file_hashes WHERE file_path = ?', (path,))
                result = cursor.fetchone()
                status = 'Unchanged'
                version = 1
                change_type = 'New'

                if result:
                    stored_hash, stored_alg, version = result
                    if stored_hash == hash_val and stored_alg == algorithm:
                        status = 'Unchanged'
                    else:
                        status = 'Modified'
                        version += 1
                        change_type = 'Modified'
                        cursor.execute('''
                            INSERT INTO file_history (file_path, hash, algorithm, change_type, timestamp)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (path, hash_val, algorithm, change_type, datetime.now()))
                else:
                    cursor.execute('''
                        INSERT INTO file_history (file_path, hash, algorithm, change_type, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (path, hash_val, algorithm, 'New', datetime.now()))

                cursor.execute('''
                    INSERT OR REPLACE INTO file_hashes (file_path, hash, algorithm, status, last_checked, version)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (path, hash_val, algorithm, status, datetime.now(), version))

            conn.commit()
        print(f"Stored {len(file_hashes)} file hashes in database")
    except Exception as e:
        print(f"Error storing hashes: {e}")

def store_merkle_root(root_hash):
    """Stores the current Merkle root with timestamp."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM merkle_root")
            cursor.execute("INSERT INTO merkle_root (id, root, timestamp) VALUES (1, ?, ?)",
                           (root_hash, datetime.now()))
            conn.commit()
        print(f"Stored Merkle root: {root_hash}")
    except Exception as e:
        print(f"Error storing Merkle root: {e}")

def add_tamper_event(file_path, old_root, new_root):
    """Logs tampering event into the database."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO tamper_log (file_path, old_root, new_root)
                VALUES (?, ?, ?)
            ''', (file_path, old_root, new_root))
            conn.commit()
        print(f"Logged tamper event for {file_path}")
    except Exception as e:
        print(f"Error logging tamper event: {e}")

def get_previous_merkle_root():
    """Retrieves the previous Merkle root."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT root FROM merkle_root WHERE id = 1")
            row = cursor.fetchone()
            return row[0] if row else None
    except Exception as e:
        print(f"Error retrieving Merkle root: {e}")
        return None

# --- Hasher Functions ---
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
    try:
        if not os.path.exists(directory):
            print(f"Directory {directory} does not exist")
            return hash_map
        for root, dirs, files in os.walk(directory):
            for name in files:
                filepath = os.path.join(root, name)
                file_hash = compute_file_hash(filepath, algo)
                if file_hash:
                    hash_map[filepath] = file_hash
        print(f"Hashed {len(hash_map)} files in {directory}")
    except Exception as e:
        print(f"Error hashing files in {directory}: {e}")
    return hash_map

# --- Merkle Tree Functions ---
def hash_pair(left, right, algo='sha256'):
    h = hashlib.new(algo)
    h.update((left + right).encode())
    return h.hexdigest()

def build_merkle_tree(file_hashes: dict, algo='sha256'):
    """Build a Merkle Tree and return the root hash."""
    if not file_hashes:
        return None, []
    leaves = [h for _, h in sorted(file_hashes.items())]
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

# --- Report Functions ---
def export_tamper_log_to_csv(csv_filename="tamper_report.csv"):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tamper_log ORDER BY timestamp DESC")
            rows = cursor.fetchall()
            with open(csv_filename, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "File Path", "Old Root", "New Root", "Timestamp"])
                writer.writerows(rows)
            print(f"✅ Tamper report exported to {csv_filename}")
    except Exception as e:
        print(f"Error exporting tamper log: {e}")

# --- Flask Routes ---
@app.route('/')
def index():
    print("Serving dashboard")
    return render_template_string(index_html)

@app.route('/api/files')
def get_files():
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT file_path, hash, algorithm, status, last_checked, version FROM file_hashes ORDER BY last_checked DESC')
            files = [dict(row) for row in cursor.fetchall()]
            for file in files:
                file['filename'] = os.path.basename(file['file_path'])
                file['id'] = file['file_path']  # Use file_path as ID for history lookup
            print(f"Fetched {len(files)} files from database")
            return jsonify(files)
    except Exception as e:
        print(f"Error fetching files: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/<path:file_id>')
def get_file_history(file_id):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM file_history WHERE file_path = ? ORDER BY timestamp DESC', (file_id,))
            history = [dict(row) for row in cursor.fetchall()]
            print(f"Fetched history for file_id {file_id}")
            return jsonify(history)
    except Exception as e:
        print(f"Error fetching file history: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/tamper_log')
def get_tamper_log():
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM tamper_log ORDER BY timestamp DESC')
            tamper_log = [dict(row) for row in cursor.fetchall()]
            print(f"Fetched {len(tamper_log)} tamper log entries")
            return jsonify(tamper_log)
    except Exception as e:
        print(f"Error fetching tamper log: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        directory = data.get('directory', MONITOR_DIR)
        algorithm = data.get('algorithm', HASH_ALGO).lower()
        print(f"Received scan request for directory: {directory} with algorithm: {algorithm}")

        if algorithm not in hashlib.algorithms_guaranteed:
            print(f"Invalid hash algorithm: {algorithm}")
            return jsonify({'status': 'error', 'message': 'Invalid hash algorithm'}), 400

        # Normalize directory path
        directory = os.path.abspath(directory)
        print(f"Normalized directory path: {directory}")
        if not os.path.exists(directory):
            print(f"Directory does not exist: {directory}")
            return jsonify({'status': 'error', 'message': f'Directory {directory} does not exist'}), 400

        hashes = hash_all_files_in_directory(directory, algorithm)
        if not hashes:
            print(f"No files found in directory: {directory}")
            return jsonify({'status': 'warning', 'message': 'No files found in directory'})

        old_root = get_previous_merkle_root()
        new_root, _ = build_merkle_tree(hashes, algorithm)

        if old_root and old_root != new_root:
            print("⚠️ FILE TAMPERING DETECTED!")
            add_tamper_event(directory, old_root, new_root)
            send_alert(directory, old_root, new_root)

        store_hashes(hashes, algorithm)
        store_merkle_root(new_root)
        print("Scan completed successfully")
        return jsonify({'status': 'success'})
    except Exception as e:
        print(f"Error during scan: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# --- Monitor Functions ---
class IntegrityMonitorHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        if event.is_directory:
            return

        print(f"\n📡 Detected change: {event.src_path}")
        hashes = hash_all_files_in_directory(MONITOR_DIR, HASH_ALGO)
        new_root, _ = build_merkle_tree(hashes)
        print(f"🔐 New Merkle Root: {new_root}")
        old_root = get_previous_merkle_root()
        print(f"📦 Stored Merkle Root: {old_root}")

        if new_root != old_root:
            print("⚠️ FILE TAMPERING DETECTED!")
            send_alert(event.src_path, old_root, new_root)
            add_tamper_event(event.src_path, old_root, new_root)
            store_hashes(hashes, HASH_ALGO)
            store_merkle_root(new_root)
        else:
            print("✅ No tampering. File change was safe.")

def send_alert(changed_file, old_root, new_root):
    print(f"📣 Sending alert: {changed_file} was modified!")
    try:
        discord_payload = {
            "content": f"🚨 **File Tampering Detected**\n\n📄 **File**: `{changed_file}`\n🧾 **Old Root**: `{old_root}`\n🆕 **New Root**: `{new_root}`"
        }
        response = requests.post(WEBHOOK_URL, json=discord_payload)
        if response.status_code == 204:
            print("✅ Discord alert sent.")
        else:
            print(f"❌ Failed to send Discord alert. Status: {response.status_code}")
    except Exception as e:
        print(f"❌ Discord webhook error: {e}")

def start_monitoring():
    init_db()
    print(f"🛰️ Monitoring started on folder: {MONITOR_DIR}")
    event_handler = IntegrityMonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, path=MONITOR_DIR, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# --- HTML Template for Dashboard ---
index_html = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>File Integrity Monitoring Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="bg-gray-100 font-sans">
<div class="container mx-auto p-6">
  <h1 class="text-3xl font-bold text-center mb-6">File Integrity Monitoring Dashboard</h1>

  <div class="flex space-x-4 mb-6">
    <input id="directory" type="text" placeholder="Enter directory path (default: ./monitored_files)"
           class="flex-1 p-2 border rounded" value="./monitored_files" />
    <select id="algorithm" class="p-2 border rounded">
      <option value="sha256">SHA-256</option>
      <option value="sha1">SHA-1</option>
      <option value="md5">MD5</option>
    </select>
    <button id="scanButton" class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">
      Scan Directory
    </button>
  </div>

  <div id="errorMessage" class="text-red-600 mb-4 hidden"></div>
  <div id="successMessage" class="text-green-600 mb-4 hidden"></div>

  <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
    <div class="bg-white p-4 rounded shadow">
      <h2 class="text-xl font-semibold mb-4">File Status Overview</h2>
      <canvas id="statusChart"></canvas>
    </div>
    <div class="bg-white p-4 rounded shadow">
      <h2 class="text-xl font-semibold mb-4">Version Changes</h2>
      <canvas id="changesChart"></canvas>
    </div>
    <div class="bg-white p-4 rounded shadow col-span-2">
      <h2 class="text-xl font-semibold mb-4">Monitored Files</h2>
      <table class="w-full">
        <thead><tr class="bg-gray-200">
          <th class="p-2 text-left">Filename</th>
          <th class="p-2 text-left">Status</th>
          <th class="p-2 text-left">Hash Algorithm</th>
          <th class="p-2 text-left">Last Checked</th>
          <th class="p-2 text-left">Version</th>
          <th class="p-2 text-left">Actions</th>
        </tr></thead>
        <tbody id="fileTable"></tbody>
      </table>
    </div>
    <div class="bg-white p-4 rounded shadow col-span-2">
      <h2 class="text-xl font-semibold mb-4">Tamper Log</h2>
      <table class="w-full">
        <thead><tr class="bg-gray-200">
          <th class="p-2 text-left">ID</th>
          <th class="p-2 text-left">File Path</th>
          <th class="p-2 text-left">Old Root</th>
          <th class="p-2 text-left">New Root</th>
          <th class="p-2 text-left">Timestamp</th>
        </tr></thead>
        <tbody id="tamperTable"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
function showError(message) {
  const errorDiv = document.getElementById('errorMessage');
  const successDiv = document.getElementById('successMessage');
  errorDiv.textContent = message;
  errorDiv.classList.remove('hidden');
  successDiv.classList.add('hidden');
}

function showSuccess(message) {
  const errorDiv = document.getElementById('errorMessage');
  const successDiv = document.getElementById('successMessage');
  successDiv.textContent = message;
  successDiv.classList.remove('hidden');
  errorDiv.classList.add('hidden');
}

async function loadFiles() {
  try {
    console.log('Loading files...');
    const fileResponse = await fetch('/api/files');
    if (!fileResponse.ok) throw new Error('Failed to fetch files: ' + fileResponse.statusText);
    const files = await fileResponse.json();
    console.log('Fetched files:', files);

    const table = document.getElementById('fileTable');
    table.innerHTML = files.map(file => `
      <tr>
        <td class="p-2">${file.filename}</td>
        <td class="p-2">
          <span class="px-2 py-1 rounded ${
            file.status === 'Unchanged' ? 'bg-green-100 text-green-700' :
            file.status === 'Modified' ? 'bg-yellow-100 text-yellow-700' :
            'bg-blue-100 text-blue-700'
          }">${file.status}</span>
        </td>
        <td class="p-2">${file.algorithm.toUpperCase()}</td>
        <td class="p-2">${new Date(file.last_checked).toLocaleString()}</td>
        <td class="p-2">${file.version}</td>
        <td class="p-2"><button onclick="viewHistory('${file.id.replace(/'/g, '\\'')}')" class="text-blue-600 hover:underline">View History</button></td>
      </tr>
    `).join('');

    const statusCounts = files.reduce((acc, file) => {
      acc[file.status] = (acc[file.status] || 0) + 1;
      return acc;
    }, {});
    new Chart(document.getElementById('statusChart'), {
      type: 'pie',
      data: {
        labels: Object.keys(statusCounts),
        datasets: [{ data: Object.values(statusCounts), backgroundColor: ['#34D399', '#FBBF24', '#3B82F6'] }]
      },
      options: { plugins: { legend: { position: 'bottom' } }, responsive: true }
    });

    new Chart(document.getElementById('changesChart'), {
      type: 'line',
      data: {
        labels: files.map(f => new Date(f.last_checked).toLocaleDateString()),
        datasets: [{
          label: 'File Version',
          data: files.map(f => f.version),
          borderColor: '#3B82F6',
          fill: false
        }]
      },
      options: { responsive: true, scales: { y: { beginAtZero: true } } }
    });

    const tamperResponse = await fetch('/api/tamper_log');
    if (!tamperResponse.ok) throw new Error('Failed to fetch tamper log: ' + tamperResponse.statusText);
    const tamperLog = await tamperResponse.json();
    console.log('Fetched tamper log:', tamperLog);

    const tamperTable = document.getElementById('tamperTable');
    tamperTable.innerHTML = tamperLog.map(log => `
      <tr>
        <td class="p-2">${log.id}</td>
        <td class="p-2">${log.file_path}</td>
        <td class="p-2">${log.old_root ? log.old_root.slice(0, 10) + '...' : 'N/A'}</td>
        <td class="p-2">${log.new_root ? log.new_root.slice(0, 10) + '...' : 'N/A'}</td>
        <td class="p-2">${new Date(log.timestamp).toLocaleString()}</td>
      </tr>
    `).join('');
  } catch (error) {
    console.error('Error loading files:', error);
    showError('Error loading data: ' + error.message);
  }
}

async function scanFiles() {
  try {
    const directory = document.getElementById('directory').value || './monitored_files';
    const algorithm = document.getElementById('algorithm').value;
    console.log('Scanning directory:', directory, 'with algorithm:', algorithm);

    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ directory, algorithm })
    });
    const result = await response.json();
    console.log('Scan result:', result);

    if (!response.ok || result.status !== 'success') {
      throw new Error(result.message || 'Scan failed');
    }

    showSuccess('Scan completed successfully');
    await loadFiles();
  } catch (error) {
    console.error('Error during scan:', error);
    showError('Error scanning directory: ' + error.message);
  }
}

async function viewHistory(fileId) {
  try {
    console.log('Viewing history for fileId:', fileId);
    const res = await fetch('/api/history/' + encodeURIComponent(fileId));
    if (!res.ok) throw new Error('Failed to fetch history: ' + res.statusText);
    const history = await res.json();
    console.log('Fetched history:', history);
    alert('File History:\n' + history.map(h => `${new Date(h.timestamp).toLocaleString()} — ${h.change_type} (${h.algorithm.toUpperCase()}): ${h.hash.slice(0, 10)}...`).join('\n'));
  } catch (error) {
    console.error('Error viewing history:', error);
    showError('Error viewing history: ' + error.message);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  console.log('Document loaded, attaching event listener to scan button');
  const scanButton = document.getElementById('scanButton');
  if (scanButton) {
    scanButton.addEventListener('click', scanFiles);
  } else {
    console.error('Scan button not found');
  }
  loadFiles();
});
</script>
</body>
</html>
"""

# --- Main Function ---
def main():
    print("📁 Scanning folder:", MONITOR_DIR)
    init_db()
    hashes = hash_all_files_in_directory(MONITOR_DIR, HASH_ALGO)
    print("\n🧾 File Hashes:")
    for path, h in hashes.items():
        print(f"{path} => {h}")
    merkle_root, tree = build_merkle_tree(hashes)
    print("\n🌲 Merkle Tree:")
    for i, level in enumerate(tree):
        print(f"Level {i}:")
        for node in level:
            print(f"  {node}")
    print(f"\n✅ Merkle Root: {merkle_root}")
    store_hashes(hashes, HASH_ALGO)
    store_merkle_root(merkle_root)
    print("\n📥 Stored hashes and Merkle root in file_hashes.db.")
    export_tamper_log_to_csv()

# --- Execution ---
if __name__ == "__main__":
    # Ensure the monitored directory exists
    os.makedirs(MONITOR_DIR, exist_ok=True)
    test_file_path = os.path.join(MONITOR_DIR, "test.txt")
    if not os.path.exists(test_file_path):
        with open(test_file_path, "w") as f:
            f.write("This is a test file for integrity monitoring.")
        print(f"Created test file at {test_file_path}")

    # Run initial scan to populate database
    print("Running initial scan...")
    main()

    # Start Flask app
    app.run(debug=True, use_reloader=False)
    # To test monitoring locally, uncomment the following line:
    # start_monitoring()