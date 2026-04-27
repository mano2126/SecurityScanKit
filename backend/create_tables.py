import sqlite3
import os

db_path = r'D:\project\security-scan\data\ssk.db'
conn = sqlite3.connect(db_path)

conn.execute('''
CREATE TABLE IF NOT EXISTS divisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    sort_order INTEGER DEFAULT 0
)
''')

conn.execute('''
CREATE TABLE IF NOT EXISTS departments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    division_name TEXT DEFAULT '',
    sort_order INTEGER DEFAULT 0
)
''')

conn.commit()

# 확인
tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print("DB 테이블 목록:")
for t in tables:
    print(f"  - {t[0]}")

conn.close()
print("완료!")