"""inspect_latest.py

Print diagnostics for the most recent ledger entry and DB file record.
Usage: python inspect_latest.py
"""
import json
import os
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / "ledger.json"
DB = ROOT / "securetransfer.db"

def show_ledger():
    if not LEDGER.exists():
        print("ledger.json not found")
        return
    try:
        ledger = json.load(open(LEDGER, "r", encoding="utf-8"))
    except Exception as e:
        print(f"Failed to read ledger.json: {e}")
        return
    if not ledger:
        print("ledger.json is empty")
        return
    last = ledger[-1]
    print("--- Last ledger entry ---")
    print(json.dumps(last, indent=2))
    entry = last.get("entry", {})
    storage = entry.get("storage")
    print("storage (repr):", repr(storage))
    if storage:
        p = Path(storage)
        print("storage absolute:", str(p))
        print("exists:", p.exists())
        try:
            print("size:", p.stat().st_size)
        except Exception as e:
            print("size: N/A (error)", e)

def show_db():
    if not DB.exists():
        print("securetransfer.db not found")
        return
    try:
        conn = sqlite3.connect(str(DB))
        cur = conn.cursor()
        cur.execute('SELECT id, owner_id, recipient_id, filename, storage_path, sha3, created_at FROM files ORDER BY id DESC LIMIT 1')
        row = cur.fetchone()
        conn.close()
        print('--- Last DB file record ---')
        print(row)
        if row and row[4]:
            sp = Path(row[4])
            print('storage_path repr:', repr(row[4]))
            print('exists:', sp.exists())
            try:
                print('size:', sp.stat().st_size)
            except Exception as e:
                print('size: N/A (error)', e)
    except Exception as e:
        print('Failed to query DB:', e)

if __name__ == '__main__':
    show_ledger()
    print()
    show_db()
