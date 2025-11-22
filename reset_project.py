"""reset_project.py

Safely remove project runtime data to return to a fresh state.

Deletes:
- securetransfer.db
- ledger.json
- all files under storage/
- all files under decrypted/
- optional: sftp_uploads/

This script asks for confirmation unless run with --yes.
"""
import argparse
import os
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB = ROOT / "securetransfer.db"
LEDGER = ROOT / "ledger.json"
STORAGE = ROOT / "storage"
DECRYPTED = ROOT / "decrypted"
SFTP_UPLOADS = ROOT / "sftp_uploads"

def remove_file(p: Path):
    if p.exists():
        try:
            p.unlink()
            print(f"Removed file: {p}")
        except Exception as e:
            print(f"Failed to remove {p}: {e}")

def clear_dir(p: Path):
    if p.exists() and p.is_dir():
        for child in p.iterdir():
            try:
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
            except Exception as e:
                print(f"Failed to remove {child}: {e}")
        print(f"Cleared directory: {p}")
    else:
        p.mkdir(parents=True, exist_ok=True)
        print(f"Created directory: {p}")

def main(yes: bool, include_sftp: bool):
    print("Project reset — this will remove runtime data and prepare a fresh state.")
    targets = [DB, LEDGER, STORAGE, DECRYPTED]
    if include_sftp:
        targets.append(SFTP_UPLOADS)

    print("The following will be removed/cleared:")
    for t in targets:
        print(" -", t.relative_to(ROOT))

    if not yes:
        resp = input("Proceed? Type 'yes' to continue: ").strip().lower()
        if resp != 'yes':
            print("Aborted by user.")
            return

    # remove DB and ledger
    remove_file(DB)
    remove_file(LEDGER)

    # clear directories
    clear_dir(STORAGE)
    clear_dir(DECRYPTED)

    if include_sftp:
        clear_dir(SFTP_UPLOADS)

    # create an empty ledger.json so app doesn't error
    try:
        with open(LEDGER, 'w', encoding='utf-8') as f:
            f.write('[]')
        print(f"Initialized empty {LEDGER.relative_to(ROOT)}")
    except Exception as e:
        print(f"Failed to write empty ledger: {e}")

    print("Reset complete. When you run the app it will recreate the database and ledger as needed.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Reset project runtime data (DB, ledger, storage).')
    parser.add_argument('--yes', action='store_true', help='Do not prompt for confirmation')
    parser.add_argument('--include-sftp', action='store_true', help='Also clear sftp_uploads folder')
    args = parser.parse_args()
    main(args.yes, args.include_sftp)
