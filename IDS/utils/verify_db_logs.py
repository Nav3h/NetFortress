# Verify the contents of the logs table

import sqlite3

def verify_db_logs():
    conn = sqlite3.connect('attack_logs.db')
    c = conn.cursor()
    c.execute("SELECT * FROM logs")
    rows = c.fetchall()
    for row in rows:
        print(row)
    conn.close()

if __name__ == "__main__":
    verify_db_logs()