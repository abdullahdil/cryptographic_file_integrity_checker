# monitor.py

import time
import os
import sqlite3
import smtplib
import requests
from email.message import EmailMessage
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from hasher import hash_all_files_in_directory
from merkle import build_merkle_tree
from db import init_db, store_hashes, store_merkle_root, add_tamper_event
import config

DB_PATH = config.DB_FILE

def get_previous_merkle_root():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT root FROM merkle_root WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

class IntegrityMonitorHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        if event.is_directory:
            return  # Ignore directory events

        print(f"\n📡 Detected change: {event.src_path}")

        # Step 1: Rehash all files
        hashes = hash_all_files_in_directory(config.MONITOR_DIR, config.HASH_ALGO)

        # Step 2: Build new Merkle tree
        new_root, _ = build_merkle_tree(hashes)
        print(f"🔐 New Merkle Root: {new_root}")

        # Step 3: Compare with stored Merkle root
        old_root = get_previous_merkle_root()
        print(f"📦 Stored Merkle Root: {old_root}")

        if new_root != old_root:
            print("⚠️ FILE TAMPERING DETECTED!")
            send_alert(event.src_path, old_root, new_root)

            # Log the tampering event
            add_tamper_event(event.src_path, old_root, new_root)

            # Step 4: Update DB with new hashes and root
            store_hashes(hashes)
            store_merkle_root(new_root)
        else:
            print("✅ No tampering. File change was safe.")

def send_alert(changed_file, old_root, new_root):
    print(f"📣 Sending alert: {changed_file} was modified!")

    subject = "🚨 File Tampering Detected"
    body = f"""\nA change was detected in a monitored file.

🗂️ File: {changed_file}
🔐 Previous Merkle Root: {old_root}
🆕 New Merkle Root: {new_root}

Please investigate the change immediately."""

    # Discord Webhook Alert
    try:
        discord_payload = {
            "content": f"🚨 **File Tampering Detected**\n\n📄 **File**: `{changed_file}`\n🧾 **Old Root**: `{old_root}`\n🆕 **New Root**: `{new_root}`"
        }
        response = requests.post(config.WEBHOOK_URL, json=discord_payload)

        if response.status_code == 204:
            print("✅ Discord alert sent.")
        else:
            print(f"❌ Failed to send Discord alert. Status: {response.status_code}")
    except Exception as e:
        print(f"❌ Discord webhook error: {e}")

def start_monitoring():
    init_db()
    print(f"🛰️ Monitoring started on folder: {config.MONITOR_DIR}")
    event_handler = IntegrityMonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, path=config.MONITOR_DIR, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
