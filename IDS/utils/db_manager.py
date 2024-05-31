import sqlite3
from hashlib import sha256

def create_connection(db_file):
    return sqlite3.connect(db_file)

def create_table(conn):
    sql_create_table = """CREATE TABLE IF NOT EXISTS detections (
                            id INTEGER PRIMARY KEY,
                            attack_type TEXT NOT NULL,
                            src_ip TEXT NOT NULL,
                            dst_ip TEXT NOT NULL,
                            timestamp TEXT NOT NULL,
                            hash TEXT NOT NULL
                          );"""
    cursor = conn.cursor()
    cursor.execute(sql_create_table)

def insert_detection(conn, detection):
    sql_insert = """INSERT INTO detections (attack_type, src_ip, dst_ip, timestamp, hash) 
                    VALUES (?, ?, ?, ?, ?);"""
    cursor = conn.cursor()
    cursor.execute(sql_insert, detection)
    conn.commit()

def hash_detection(detection):
    sha = sha256()
    sha.update("".join(detection).encode('utf-8'))
    return sha.hexdigest()