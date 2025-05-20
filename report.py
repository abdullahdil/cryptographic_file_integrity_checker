
# report.py
import sqlite3
import csv
from config import DB_FILE

def export_tamper_log_to_csv(csv_filename="tamper_report.csv"):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tamper_log ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()

    with open(csv_filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "File Path", "Old Root", "New Root", "Timestamp"])
        writer.writerows(rows)

    print(f"✅ Tamper report exported to {csv_filename}")

if __name__ == "__main__":
    export_tamper_log_to_csv()
