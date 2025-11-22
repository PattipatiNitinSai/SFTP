

import os
import io
import json
import sqlite3
import base64
import hashlib
import secrets
import pathlib
from datetime import datetime, timezone
from typing import Tuple, Dict, Any, Optional

import streamlit as st
from PIL import Image, ImageDraw, ImageFont
import traceback
import posixpath

# Crypto
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
 
# Optional paramiko for real SFTP
try:
    import paramiko
    HAS_PARAMIKO = True
except Exception:
    HAS_PARAMIKO = False
 
# -------------------------
# Paths & storage
# -------------------------
BASE_DIR = pathlib.Path(".").resolve()
DB_PATH = BASE_DIR / "securetransfer.db"
UPLOAD_DIR = BASE_DIR / "storage"           # encrypted files
DECRYPT_DIR = BASE_DIR / "decrypted"        # decrypted downloads (for testing)
LEDGER_PATH = BASE_DIR / "ledger.json"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DECRYPT_DIR, exist_ok=True)
 
def rsa_encrypt(pub_pem: bytes, plaintext: bytes) -> bytes:
    pub = serialization.load_pem_public_key(pub_pem)
    ct = pub.encrypt(plaintext, asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return ct

def rsa_decrypt(priv_pem: bytes, ciphertext: bytes) -> bytes:
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    pt = priv.decrypt(ciphertext, asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return pt

def rsa_sign(priv_pem: bytes, message: bytes) -> bytes:
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    sig = priv.sign(message, asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH), hashes.SHA256())
    return sig

def rsa_verify(pub_pem: bytes, message: bytes, signature: bytes) -> bool:
    pub = serialization.load_pem_public_key(pub_pem)
    try:
        pub.verify(signature, message, asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except Exception:
        return False

# AES-GCM encrypt/decrypt (file content)
def aesgcm_encrypt(plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return key, nonce, ct

def aesgcm_decrypt(key: bytes, nonce: bytes, ct: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


# Ledger / hashing helpers
def ensure_ledger():
    if not LEDGER_PATH.exists():
        with open(LEDGER_PATH, "w") as f:
            json.dump([], f)

def append_ledger(entry: Dict[str, Any]) -> Dict[str, Any]:
    ensure_ledger()
    with open(LEDGER_PATH, "r+", encoding="utf-8") as f:
        ledger = json.load(f)
        prev_hash = ledger[-1]["entry_hash"] if ledger else ""
        entry_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "entry": entry,
            "prev_hash": prev_hash
        }
        entry_bytes = json.dumps(entry_record, sort_keys=True).encode()
        entry_hash = hashlib.sha3_512(entry_bytes).hexdigest()
        entry_record["entry_hash"] = entry_hash
        ledger.append(entry_record)
        f.seek(0)
        json.dump(ledger, f, indent=2)
    return entry_record


def notify_tamper(file_id: int, filename: str, owner: str, recorded_sha3: str, computed_sha3: str) -> Dict[str, Any]:
    """Create a tamper alert entry in the ledger so admins and users can see the incident.

    Returns the created ledger record.
    """
    alert = {
        "event": "tamper_alert",
        "file_id": file_id,
        "filename": filename,
        "owner": owner,
        "recorded_sha3": recorded_sha3,
        "computed_sha3": computed_sha3
    }
    rec = append_ledger(alert)
    # also store in session_state for quick UI feedback (non-persistent)
    try:
        if 'tamper_alerts' not in st.session_state:
            st.session_state['tamper_alerts'] = []
        st.session_state['tamper_alerts'].append(rec)
    except Exception:
        pass
    return rec


def simulate_tamper(file_id: int) -> Tuple[bool, str]:
    """Simulate tampering of a stored file (local storage only).

    This flips a single byte in the stored encrypted blob so integrity checks will fail.
    Returns (success, message).
    """
    try:
        rec = get_file_record(file_id)
        if not rec:
            return False, "File record not found"
        _, owner_id, recipient_id, filename, storage_path, sha3_rec, signature, key_wrapped, nonce, filesize, created_at = rec
        # only support local storage path for simulation
        if not storage_path or isinstance(storage_path, str) and storage_path.startswith('sftp://'):
            return False, "Simulate tamper supports local files only (not remote SFTP refs)."
        p = pathlib.Path(storage_path)
        if not p.exists():
            return False, "Stored file not found on disk"
        # read bytes, flip a byte in the middle, write back
        data = p.read_bytes()
        if not data:
            return False, "Stored file is empty"
        idx = len(data) // 2
        b = data[idx]
        # flip low bit
        newb = (b ^ 0x01) & 0xFF
        newdata = data[:idx] + bytes([newb]) + data[idx+1:]
        p.write_bytes(newdata)
        return True, f"Tampered local file: {p}"
    except Exception as e:
        return False, f"Simulate tamper failed: {e}"

def compute_sha3_512(data: bytes) -> str:
    h = hashlib.sha3_512()
    h.update(data)
    return h.hexdigest()

# Password-based key derivation (to protect user's private key at rest)
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(length=32, salt=salt, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def encrypt_private_key_with_password(private_key_pem: bytes, password: str) -> Tuple[bytes, bytes]:
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, private_key_pem, None)
    return salt + nonce + ct, b""

def decrypt_private_key_with_password(blob: bytes, password: str) -> bytes:
    salt = blob[:16]; nonce = blob[16:28]; ct = blob[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


# RSA keypair generation
def generate_rsa_keypair() -> Tuple[bytes, bytes]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem


# Safe rerun wrapper: some Streamlit installs may not expose experimental_rerun
def safe_rerun():
    try:
        # preferred API
        st.experimental_rerun()
    except Exception:
        # fallback: mark session and stop execution to let UI refresh on next interaction
        try:
            st.session_state['_needs_rerun'] = True
        except Exception:
            pass
        st.stop()


def render_table(rows: list, columns: Optional[list] = None, max_rows: int = 200):
    """Render a list of dicts as a table. Prefer pandas/st.table when available; fallback to Markdown table."""
    if not rows:
        st.info("No rows to display.")
        return
    # respect max_rows
    to_show = rows[-max_rows:]
    # try pandas
    try:
        import pandas as pd
        df = pd.DataFrame(to_show)
        if columns:
            # ensure columns exist in df
            cols = [c for c in columns if c in df.columns]
            if cols:
                df = df[cols]
        st.table(df)
        return
    except Exception:
        # build markdown table
        if columns:
            cols = columns
        else:
            # collect keys in order of first row
            cols = list(to_show[0].keys())
        # header
        md = "| " + " | ".join(cols) + " |\n"
        md += "|" + "---|" * len(cols) + "\n"
        for r in to_show:
            row_vals = []
            for c in cols:
                v = r.get(c, "")
                s = str(v)
                s = s.replace("|", "\\|")
                row_vals.append(s)
            md += "| " + " | ".join(row_vals) + " |\n"
        st.markdown(md)


# SFTP helper: fetch a remote file given a storage_ref like 'sftp://host:port/remote/path'
def fetch_file_via_sftp(storage_ref: str, sftp_cfg: Dict[str, Any]) -> Optional[bytes]:
    if not HAS_PARAMIKO:
        return None
    try:
        # parse storage_ref
        # expected format: sftp://host:port/remote/path  or sftp://host/remote/path
        if not storage_ref.startswith('sftp://'):
            return None
        without = storage_ref[len('sftp://'):]
        # split host[:port] and remote path
        if '/' in without:
            hostpart, remote_path = without.split('/', 1)
            remote_path = '/' + remote_path
        else:
            hostpart = without
            remote_path = '/'
        if ':' in hostpart:
            host, port = hostpart.split(':', 1)
            port = int(port)
        else:
            host = hostpart; port = int(sftp_cfg.get('port', 22))

        transport = paramiko.Transport((host, port))
        # prefer key-auth if provided in sftp_cfg
        pkey = None
        if sftp_cfg.get('use_key'):
            key_str = sftp_cfg.get('pkey_str')
            key_path = sftp_cfg.get('key_path')
            key_pass = sftp_cfg.get('key_passphrase')
            if key_str:
                pkey = _load_pkey_from_string(key_str, key_pass)
            elif key_path:
                try:
                    pkey = paramiko.RSAKey.from_private_key_file(key_path, password=key_pass)
                except Exception:
                    try:
                        pkey = paramiko.Ed25519Key.from_private_key_file(key_path, password=key_pass)
                    except Exception:
                        pkey = None
        if pkey is not None:
            transport.connect(username=sftp_cfg.get('user'), pkey=pkey)
        else:
            transport.connect(username=sftp_cfg.get('user'), password=sftp_cfg.get('password'))
        sftp = paramiko.SFTPClient.from_transport(transport)
        # read remote file into memory
        with sftp.open(remote_path, 'rb') as rf:
            data = rf.read()
        sftp.close(); transport.close()
        return data
    except Exception:
        return None

# Image watermarking
def watermark_image_bytes(image_bytes: bytes, watermark_text: str = "SecureTransfer") -> bytes:
    with Image.open(io.BytesIO(image_bytes)).convert("RGBA") as img:
        txt = Image.new("RGBA", img.size, (255,255,255,0))
        draw = ImageDraw.Draw(txt)
        try:
            font = ImageFont.truetype("arial.ttf", 20)
        except Exception:
            font = ImageFont.load_default()
        # prefer textbbox (newer Pillow) with fallback to textsize for compatibility
        try:
            bbox = draw.textbbox((0, 0), watermark_text, font=font)
            w = bbox[2] - bbox[0]
            h = bbox[3] - bbox[1]
        except Exception:
            w, h = draw.textsize(watermark_text, font=font)
        pos = (img.size[0] - w - 10, img.size[1] - h - 10)
        draw.text(pos, watermark_text, fill=(255,255,255,180), font=font)
        combined = Image.alpha_composite(img, txt)
        out = io.BytesIO()
        combined.convert("RGB").save(out, format="JPEG")
        return out.getvalue()

# -------------------------
# DB: sqlite for users & metadata
# -------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    role TEXT,
                    password_hash TEXT,
                    priv_enc BLOB,
                    pub_pem BLOB,
                    created_at TEXT
                  )""")
    # include recipient_id so we can record who may unwrap the key
    cur.execute("""CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY,
                    owner_id INTEGER,
                    recipient_id INTEGER,
                    filename TEXT,
                    storage_path TEXT,
                    sha3 TEXT,
                    signature BLOB,
                    key_wrapped BLOB,
                    nonce BLOB,
                    filesize INTEGER,
                    created_at TEXT,
                    FOREIGN KEY(owner_id) REFERENCES users(id)
                  )""")
    # If the table existed before without recipient_id, add the column
    cur.execute("PRAGMA table_info(files)")
    cols = [r[1] for r in cur.fetchall()]
    if 'recipient_id' not in cols:
        try:
            cur.execute("ALTER TABLE files ADD COLUMN recipient_id INTEGER")
        except Exception:
            # some sqlite versions / states might not allow alter; ignore and proceed
            pass
    conn.commit()
    conn.close()

def list_user_files(owner_id: int):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, filename, storage_path, sha3, created_at FROM files WHERE owner_id=?", (owner_id,))
    rows = cur.fetchall()
    conn.close()
    return rows

def get_file_record(file_id: int):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, owner_id, recipient_id, filename, storage_path, sha3, signature, key_wrapped, nonce, filesize, created_at FROM files WHERE id= ?", (file_id,))
    row = cur.fetchone()
    conn.close()
    return row


def backfill_recipient_from_ledger() -> int:
    """Scan `ledger.json` for upload entries and populate `files.recipient_id` for rows missing it.
    Returns the number of files updated.
    """
    try:
        if not LEDGER_PATH.exists():
            return 0
        with open(LEDGER_PATH, "r", encoding="utf-8") as f:
            ledger = json.load(f)
    except Exception:
        return 0

    # collect upload entries
    uploads = []
    for e in ledger:
        entry = e.get("entry", {})
        if entry.get("event") == "upload":
            uploads.append({
                "storage": entry.get("storage"),
                "sha3": entry.get("sha3"),
                "filename": entry.get("filename"),
                "owner": entry.get("owner"),
                "recipient": entry.get("recipient")
            })
    if not uploads:
        return 0

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    updated = 0
    for u in uploads:
        storage = u.get("storage")
        sha3 = u.get("sha3")
        filename = u.get("filename")
        owner_username = u.get("owner")
        recipient_username = u.get("recipient")
        if not recipient_username:
            continue

        # find recipient id
        cur.execute("SELECT id FROM users WHERE username=?", (recipient_username,))
        rrow = cur.fetchone()
        if not rrow:
            continue
        rid = rrow[0]

        # try to find files by storage_path first
        rows = []
        if storage:
            cur.execute("SELECT id, recipient_id FROM files WHERE storage_path=?", (storage,))
            rows = cur.fetchall()

        # fallback to matching by owner+sha3+filename
        if not rows and owner_username and sha3 and filename:
            cur.execute("SELECT id FROM users WHERE username=?", (owner_username,))
            orow = cur.fetchone()
            if orow:
                owner_id = orow[0]
                cur.execute("SELECT id, recipient_id FROM files WHERE owner_id=? AND sha3=? AND filename=?", (owner_id, sha3, filename))
                rows = cur.fetchall()

        for row in rows:
            fid = row[0]
            existing_recipient = row[1]
            if existing_recipient is None or existing_recipient == "":
                try:
                    cur.execute("UPDATE files SET recipient_id=? WHERE id=?", (rid, fid))
                    updated += 1
                except Exception:
                    pass

    conn.commit()
    conn.close()
    return updated

def create_user(username: str, password: str, role: str = "User") -> Tuple[bool, str]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    if cur.fetchone():
        conn.close()
        return False, "Username exists"
    # generate rsa keypair
    priv_pem, pub_pem = generate_rsa_keypair()
    # encrypt private key with password-derived key
    priv_blob, _ = encrypt_private_key_with_password(priv_pem, password)
    # store password hash (use SHA3-512 salt+hash for simplicity)
    salt = secrets.token_hex(8)
    pwd_hash = hashlib.sha3_512((password + salt).encode()).hexdigest() + ":" + salt
    cur.execute("INSERT INTO users (username, role, password_hash, priv_enc, pub_pem, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (username, role, pwd_hash, priv_blob, pub_pem, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()
    return True, "User created"

def authenticate_user(username: str, password: str) -> Tuple[bool, Optional[Dict[str,Any]]]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, role, password_hash, priv_enc, pub_pem FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False, None
    _id, role, stored, priv_enc, pub_pem = row
    try:
        pwd_hash, salt = stored.split(":")
    except Exception:
        return False, None
    if hashlib.sha3_512((password + salt).encode()).hexdigest() != pwd_hash:
        return False, None
    # decrypt private key
    try:
        priv_pem = decrypt_private_key_with_password(priv_enc, password)
    except Exception:
        priv_pem = None
    return True, {"id": _id, "username": username, "role": role, "priv_pem": priv_pem, "pub_pem": pub_pem}

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, pub_pem, created_at FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {"id": row[0], "username": row[1], "role": row[2], "pub_pem": row[3], "created_at": row[4]}

def store_file_metadata(owner_id: int, recipient_id: int, filename: str, storage_path: str, sha3: str, signature: bytes, key_wrapped: bytes, nonce: bytes, filesize: int):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""INSERT INTO files (owner_id, recipient_id, filename, storage_path, sha3, signature, key_wrapped, nonce, filesize, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (owner_id, recipient_id, filename, storage_path, sha3, signature, key_wrapped, nonce, filesize, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()
    
# attempt to backfill recipient_id for older file records using ledger.json
try:
    # Ensure DB exists and tables are created before any DB operations
    try:
        init_db()
    except Exception:
        pass
    backfilled = backfill_recipient_from_ledger()
    if backfilled:
        try:
            st.info(f"Backfilled recipient_id for {backfilled} file(s) from ledger.json")
        except Exception:
            # if streamlit not ready to show messages, ignore
            pass
except Exception:
    pass

# -------------------------
# UI: Authentication
# -------------------------
if "auth" not in st.session_state:
    st.session_state.auth = None

def show_register():
    st.subheader("Create account")
    username = st.text_input("Username", key="reg_username")
    password = st.text_input("Password", type="password", key="reg_password")
    role = st.selectbox("Role", ["User", "Admin"], key="reg_role")
    if st.button("Register"):
        ok, msg = create_user(username.strip(), password, role)
        if ok:
            st.success(msg)
        else:
            st.error(msg)

def show_login():
    st.subheader("Login")
    username = st.text_input("Username", key="login_user")
    password = st.text_input("Password", type="password", key="login_pwd")
    if st.button("Login"):
        ok, info = authenticate_user(username.strip(), password)
        if ok:
            st.session_state.auth = info
            st.success(f"Logged in as {username} ({info['role']})")
            safe_rerun()
        else:
            st.error("Invalid credentials")

with st.sidebar.expander("Account", expanded=True):
    if st.session_state.auth is None:
        show_login()
        st.markdown("---")
        show_register()
    else:
        st.markdown(f"**User:** {st.session_state.auth['username']}")
        st.markdown(f"**Role:** {st.session_state.auth['role']}")
        if st.button("Logout"):
            st.session_state.auth = None
            safe_rerun()

# -------------------------
# Main app tabs
# -------------------------
# Show ledger tab to authenticated users. Admins will see all entries; regular users see filtered entries.
auth = st.session_state.get("auth")
user_role = None
username = None
if auth:
    user_role = auth.get("role")
    username = auth.get("username")
include_ledger = (auth is not None)

if include_ledger:
    tabs_names = ["Upload", "Download/Verify", "Ledger (immutable)", "Admin / Metadata", "Settings"]
else:
    tabs_names = ["Upload", "Download/Verify", "Admin / Metadata", "Settings"]

tabs = st.tabs(tabs_names)

def _get_tab(name: str):
    try:
        return tabs[tabs_names.index(name)]
    except Exception:
        return None

tab_upload = _get_tab("Upload")
tab_verify = _get_tab("Download/Verify")
tab_ledger = _get_tab("Ledger (immutable)")
tab_admin = _get_tab("Admin / Metadata")
tab_settings = _get_tab("Settings")

# Settings tab
with tab_settings:
    st.header("Settings")
    st.info("SFTP integration is optional. If paramiko is present, you can enable real SFTP upload")
    sftp_enabled = st.checkbox("Enable real SFTP upload (paramiko required)", value=False, key="sftp_enabled")
    if sftp_enabled and not HAS_PARAMIKO:
        st.warning("paramiko not installed. Install paramiko to use real SFTP.")
    sftp_host = st.text_input("SFTP Host", value="localhost")
    sftp_port = st.number_input("SFTP Port", value=22, step=1)
    sftp_user = st.text_input("SFTP Username", value="testuser")
    sftp_pass = st.text_input("SFTP Password", value="password", type="password")
    st.markdown("---")
    st.subheader("SFTP Authentication")
    use_key_auth = st.checkbox("Use SSH private key (preferred)", value=False, key="sftp_use_key")
    key_passphrase = None
    # Option 1: path to private key on server host (advanced)
    key_path = st.text_input("Private key file path on server (optional)", value="", help="Path to private key file accessible by the app process (avoid if possible)")
    # Option 2: upload private key for session only (drag & drop friendly)
    uploaded_key = st.file_uploader("Drag & drop private key (PEM/OPENSSH) — Limit 200MB • allowed: .pem .key .txt", type=["pem","key","txt"], key="sftp_key_upload")
    if uploaded_key is not None:
        # validate filename extension
        name = (uploaded_key.name or "").lower()
        allowed_ext = ('.pem', '.key', '.txt')
        if not any(name.endswith(ext) for ext in allowed_ext):
            st.error(f"Invalid file type: {uploaded_key.name}. Allowed: {', '.join(allowed_ext)}")
        else:
            try:
                data = uploaded_key.getvalue()
                max_bytes = 200 * 1024 * 1024
                if len(data) > max_bytes:
                    st.error("File too large: private key must be <= 200 MB")
                else:
                    try:
                        key_data = data.decode(errors='ignore')
                    except Exception:
                        key_data = data.decode('utf-8', errors='replace')
                    st.session_state['sftp_pkey_str'] = key_data
                    st.info("Private key loaded into session (not persisted).")
            except Exception:
                st.error("Failed to read uploaded key file.")
    # passphrase if key protected
    if use_key_auth:
        key_passphrase = st.text_input("Private key passphrase (if any)", type="password")

    # Test connection
    def _load_pkey_from_string(key_str: str, passphrase: Optional[str]):
        # Try RSA then Ed25519; paramiko expects a file-like object
        if not key_str:
            return None
        key_file = io.StringIO(key_str)
        try:
            return paramiko.RSAKey.from_private_key(key_file, password=passphrase)
        except Exception:
            key_file.seek(0)
        try:
            return paramiko.Ed25519Key.from_private_key(key_file, password=passphrase)
        except Exception:
            return None

    if st.button("Test SFTP connection"):
        if not HAS_PARAMIKO:
            st.error("paramiko not available in environment")
        else:
            transport = None
            sftp = None
            try:
                transport = paramiko.Transport((sftp_host, sftp_port))
                if use_key_auth:
                    pkey = None
                    key_string = st.session_state.get('sftp_pkey_str')
                    if key_string:
                        pkey = _load_pkey_from_string(key_string, key_passphrase)
                    elif key_path:
                        try:
                            pkey = paramiko.RSAKey.from_private_key_file(key_path, password=key_passphrase)
                        except Exception:
                            try:
                                pkey = paramiko.Ed25519Key.from_private_key_file(key_path, password=key_passphrase)
                            except Exception:
                                pkey = None
                    if pkey is None:
                        st.error("No valid private key found for key-auth. Provide uploaded key or key path.")
                    else:
                        transport.connect(username=sftp_user, pkey=pkey)
                else:
                    transport.connect(username=sftp_user, password=sftp_pass)
                sftp = paramiko.SFTPClient.from_transport(transport)
                # quick dir check
                try:
                    sftp.listdir('.')
                except Exception:
                    pass
                st.success("SFTP connection successful")
            except Exception as e:
                st.error(f"SFTP connection failed: {e}")
            finally:
                try:
                    if sftp: sftp.close()
                except Exception:
                    pass
                try:
                    if transport: transport.close()
                except Exception:
                    pass
    st.markdown("**Note**: For capstone/demo, leaving SFTP off will store encrypted files under `storage/` locally.")

# Upload tab
with tab_upload:
    st.header("Upload & Secure File")
    if st.session_state.auth is None:
        st.warning("Login or register to upload files.")
    else:
        uploaded = st.file_uploader("Select file to upload (will be encrypted locally)", key="upload_file")
        apply_watermark = st.checkbox("Apply image watermark (if file is image)", value=True)
        keep_local_copy = st.checkbox("Keep local copy after upload (optional)", value=False)
        recipient_username = st.text_input("Receiver username (recipient who will be able to unwrap the key)", value=st.session_state.auth["username"])
        if st.button("Secure Upload") and uploaded:
            # read bytes
            data = uploaded.read()
            orig_sha3 = compute_sha3_512(data)
            filesize = len(data)
            owner = get_user_by_username(st.session_state.auth["username"])
            recipient = get_user_by_username(recipient_username)
            if not recipient:
                st.error("Recipient username not found")
            else:
                # watermark if image
                if apply_watermark and uploaded.type and uploaded.type.startswith("image/"):
                    try:
                        data = watermark_image_bytes(data, watermark_text="SecureTransfer")
                        st.info("Watermark applied")
                    except Exception as e:
                        st.warning(f"Watermark failed: {e}")
                # symmetric encrypt file
                sym_key, nonce, ct = aesgcm_encrypt(data)
                # wrap symmetric key with recipient public key
                key_wrapped = rsa_encrypt(recipient["pub_pem"], sym_key)
                # sign sha3 (owner signs) using owner's private key (if available)
                # Instead: use owner's priv_pem if in session (we only keep priv_pem when user logged in and decrypted)
                priv_pem = st.session_state.auth.get("priv_pem")
                if priv_pem:
                    signature = rsa_sign(priv_pem, orig_sha3.encode())
                else:
                    # if private key not loaded decrypted (rare), sign with server ephemeral key (warn)
                    signature = b""

                # prefer SFTP upload first (if enabled); otherwise store locally
                filename = uploaded.name
                storage_name = f"{secrets.token_hex(12)}_{filename}"
                fileblob = nonce + ct

                storage_ref = None
                # build sftp cfg for helper usage
                sftp_cfg = {
                    'host': sftp_host,
                    'port': sftp_port,
                    'user': sftp_user,
                    'password': sftp_pass,
                    'use_key': bool(st.session_state.get('sftp_pkey_str') or key_path) or False,
                    'pkey_str': st.session_state.get('sftp_pkey_str'),
                    'key_path': key_path,
                    'key_passphrase': st.session_state.get('sftp_key_passphrase') or key_passphrase
                }

                if sftp_enabled and HAS_PARAMIKO:
                    # attempt to upload from memory (avoid writing local copy unless requested)
                    try:
                        transport = paramiko.Transport((sftp_host, sftp_port))
                        # auth
                        pkey = None
                        if st.session_state.get('sftp_pkey_str'):
                            pkey = _load_pkey_from_string(st.session_state.get('sftp_pkey_str'), st.session_state.get('sftp_key_passphrase') or key_passphrase)
                        elif key_path:
                            try:
                                pkey = paramiko.RSAKey.from_private_key_file(key_path, password=st.session_state.get('sftp_key_passphrase') or key_passphrase)
                            except Exception:
                                try:
                                    pkey = paramiko.Ed25519Key.from_private_key_file(key_path, password=st.session_state.get('sftp_key_passphrase') or key_passphrase)
                                except Exception:
                                    pkey = None
                        if pkey is not None:
                            transport.connect(username=sftp_user, pkey=pkey)
                        else:
                            transport.connect(username=sftp_user, password=sftp_pass)
                        sftp = paramiko.SFTPClient.from_transport(transport)

                        # try absolute remote dir first
                        remote_dir = f"/home/{sftp_user}/uploads"
                        try:
                            sftp.chdir(remote_dir)
                        except Exception:
                            # try create recursively, ignore failures
                            try:
                                parts = [p for p in remote_dir.split('/') if p]
                                cur = ''
                                if remote_dir.startswith('/'):
                                    cur = '/'
                                for part in parts:
                                    cur = posixpath.join(cur, part) if cur != '/' else '/' + part
                                    try:
                                        sftp.stat(cur)
                                    except IOError:
                                        try:
                                            sftp.mkdir(cur)
                                        except Exception:
                                            pass
                                try:
                                    sftp.chdir(remote_dir)
                                except Exception:
                                    pass
                            except Exception:
                                pass
                        remote_path = f"{remote_dir}/{storage_name}"

                        # write bytes from memory
                        from io import BytesIO
                        uploaded_ok = False
                        try:
                            bio = BytesIO(fileblob)
                            bio.seek(0)
                            sftp.putfo(bio, remote_path)
                            uploaded_ok = True
                            storage_ref = f"sftp://{sftp_host}:{sftp_port}{remote_path}"
                        except Exception:
                            # fallback to relative uploads/ beneath server cwd
                            try:
                                rel_dir = 'uploads'
                                try:
                                    sftp.stat(rel_dir)
                                except Exception:
                                    try:
                                        sftp.mkdir(rel_dir)
                                    except Exception:
                                        pass
                                rel_remote = f"{rel_dir}/{storage_name}"
                                bio = BytesIO(fileblob); bio.seek(0)
                                sftp.putfo(bio, rel_remote)
                                uploaded_ok = True
                                storage_ref = f"sftp://{sftp_host}:{sftp_port}/{rel_remote}"
                            except Exception as e:
                                st.warning(f"SFTP upload failed: {e}")
                        try:
                            sftp.close(); transport.close()
                        except Exception:
                            pass

                        # if user requested a local copy, write it
                        if keep_local_copy:
                            storage_path = UPLOAD_DIR / storage_name
                            with open(storage_path, 'wb') as f:
                                f.write(fileblob)
                            # prefer storing the SFTP ref in DB but also local copy exists

                        if storage_ref:
                            # store metadata with storage_ref (remote)
                            owner_id = owner["id"]
                            store_file_metadata(owner_id, recipient["id"], filename, storage_ref, orig_sha3, signature, key_wrapped, nonce, filesize)
                            ledger_entry = {
                                "event": "upload",
                                "owner": st.session_state.auth["username"],
                                "recipient": recipient_username,
                                "filename": filename,
                                "sha3": orig_sha3,
                                "filesize": filesize,
                                "storage": storage_ref
                            }
                            rec = append_ledger(ledger_entry)
                            st.success("File encrypted & uploaded to SFTP server")
                            st.json({"sha3": orig_sha3, "ledger_hash": rec["entry_hash"]})
                        else:
                            # fallback: save locally
                            storage_path = UPLOAD_DIR / storage_name
                            with open(storage_path, "wb") as f:
                                f.write(fileblob)
                            owner_id = owner["id"]
                            store_file_metadata(owner_id, recipient["id"], filename, str(storage_path), orig_sha3, signature, key_wrapped, nonce, filesize)
                            ledger_entry = {
                                "event": "upload",
                                "owner": st.session_state.auth["username"],
                                "recipient": recipient_username,
                                "filename": filename,
                                "sha3": orig_sha3,
                                "filesize": filesize,
                                "storage": str(storage_path)
                            }
                            rec = append_ledger(ledger_entry)
                            st.success("File encrypted & stored locally (SFTP unavailable)")
                            st.json({"sha3": orig_sha3, "ledger_hash": rec["entry_hash"]})
                    except Exception as e:
                        st.warning(f"SFTP upload failed: {e}")
                else:
                    # no SFTP: store locally (existing behavior)
                    storage_path = UPLOAD_DIR / storage_name
                    with open(storage_path, "wb") as f:
                        f.write(fileblob)
                    owner_id = owner["id"]
                    store_file_metadata(owner_id, recipient["id"], filename, str(storage_path), orig_sha3, signature, key_wrapped, nonce, filesize)
                    ledger_entry = {
                        "event": "upload",
                        "owner": st.session_state.auth["username"],
                        "recipient": recipient_username,
                        "filename": filename,
                        "sha3": orig_sha3,
                        "filesize": filesize,
                        "storage": str(storage_path)
                    }
                    rec = append_ledger(ledger_entry)
                    st.success("File encrypted & stored locally")
                    st.json({"sha3": orig_sha3, "ledger_hash": rec["entry_hash"]})

# Verify / Download tab
with tab_verify:
    st.header("Download & Verify File")
    if st.session_state.auth is None:
        st.warning("Login to verify/download files.")
    else:
        # list files available to user (owner OR recipient)
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        user_id = st.session_state.auth["id"]
        cur.execute("SELECT f.id, f.filename, u.username, f.sha3, f.created_at FROM files f JOIN users u ON f.owner_id = u.id WHERE f.owner_id=? OR f.recipient_id=?", (user_id, user_id))
        rows = cur.fetchall()
        conn.close()
        df_rows = [{"id": r[0], "filename": r[1], "owner": r[2], "sha3": r[3], "created_at": r[4]} for r in rows]
        if not df_rows:
            st.info("No files in system yet.")
        else:
            sel = st.selectbox("Select file to download/verify", options=df_rows, format_func=lambda x: f"{x['filename']} (owner:{x['owner']})")
            if st.button("Download & Verify"):
                rec = get_file_record(sel["id"])
                if not rec:
                    st.error("File record missing")
                else:
                    _, owner_id, recipient_id, filename, storage_path, sha3_rec, signature, key_wrapped, nonce, filesize, created_at = rec
                    # storage_path may be a local path or a remote sftp ref (sftp://host:port/path)
                    fileblob = None
                    if isinstance(storage_path, str) and storage_path.startswith('sftp://'):
                        # attempt to fetch via SFTP using current settings
                        sftp_cfg = {
                            'host': sftp_host,
                            'port': sftp_port,
                            'user': sftp_user,
                            'password': sftp_pass,
                            'use_key': bool(st.session_state.get('sftp_pkey_str') or key_path),
                            'pkey_str': st.session_state.get('sftp_pkey_str'),
                            'key_path': key_path,
                            'key_passphrase': st.session_state.get('sftp_key_passphrase') or key_passphrase
                        }
                        fetched = fetch_file_via_sftp(storage_path, sftp_cfg)
                        if fetched is None:
                            st.error("Stored file is remote and could not be fetched via SFTP. Check Settings and network.")
                            st.stop()
                        fileblob = fetched
                    else:
                        storage_path = pathlib.Path(storage_path)
                        if not storage_path.exists():
                            st.error("Stored file missing on disk")
                            st.stop()
                        with open(storage_path, "rb") as f:
                            fileblob = f.read()

                    # Check if current user is recipient (we must try to unwrap key with user's private key)
                    # We need user's decrypted private key in session
                    priv_pem = st.session_state.auth.get("priv_pem")
                    if not priv_pem:
                        st.warning("Your private key is not loaded in session. To decrypt, log in (the private key was decrypted at login).")
                    # attempt to unwrap symmetric key
                    try:
                        sym_key = rsa_decrypt(priv_pem, key_wrapped)
                    except Exception:
                        st.error("Could not unwrap file symmetric key with your private key (not recipient or wrong key).")
                        sym_key = None

                    # nonce is stored separately in DB as well; we'll use db nonce where possible
                    try:
                        nonce_db = nonce
                        if isinstance(nonce_db, str) or nonce_db is None:
                            nonce_db = fileblob[:12]
                            ct = fileblob[12:]
                        else:
                            # if nonce blob present (bytes), strip that length
                            ct = fileblob[len(nonce_db):] if len(fileblob) > len(nonce_db) else fileblob[12:]
                    except Exception:
                        nonce_db = fileblob[:12]; ct = fileblob[12:]

                    # decrypt if we have sym key
                    if sym_key:
                        try:
                            plain = aesgcm_decrypt(sym_key, nonce_db, ct)
                        except Exception as e_decrypt:
                            # Treat decryption failure as tampering indicator. We cannot compute plaintext hash.
                            st.write("Recorded SHA3-512:", sha3_rec)
                            try:
                                # show ciphertext hash as additional debug info
                                ct_hash = compute_sha3_512(ct)
                                st.write("Ciphertext SHA3-512 (for debugging):", ct_hash)
                            except Exception:
                                pass
                            st.error("⚠️ Tampering detected or decryption failed (integrity check unavailable due to corrupt ciphertext).")
                            st.error(f"Decryption failed: {e_decrypt}")
                            # record tamper alert in ledger
                            try:
                                notify_rec = notify_tamper(sel['id'], filename, st.session_state.auth.get('username'), sha3_rec, "decryption_failed")
                                st.warning(f"Tamper alert recorded: ledger_hash={notify_rec.get('entry_hash')}")
                            except Exception:
                                pass
                            # attempt signature verification (signature is over recorded SHA3, so independent of decryption)
                            if signature:
                                try:
                                    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
                                    c.execute("SELECT pub_pem FROM users WHERE id=?", (owner_id,)); prow = c.fetchone(); conn.close()
                                    owner_pub = prow[0] if prow else None
                                    if owner_pub:
                                        ok = rsa_verify(owner_pub, sha3_rec.encode(), signature)
                                        if ok:
                                            st.success("Signature verification passed — original provenance validated.")
                                        else:
                                            st.warning("Signature verification failed.")
                                except Exception:
                                    pass
                        else:
                            # successful decryption path
                            try:
                                new_sha3 = compute_sha3_512(plain)
                            except Exception:
                                new_sha3 = None
                            tampered = (new_sha3 != sha3_rec)
                            st.write("Recorded SHA3-512:", sha3_rec)
                            st.write("Computed SHA3-512:", new_sha3)
                            if tampered:
                                st.error("⚠️ Tampering detected! File hash mismatch.")
                                try:
                                    notify_rec = notify_tamper(sel['id'], filename, st.session_state.auth.get('username'), sha3_rec, new_sha3)
                                    st.warning(f"Tamper alert recorded: ledger_hash={notify_rec.get('entry_hash')}")
                                except Exception:
                                    pass
                            else:
                                st.success("✅ Integrity verified (hash matched).")
                            # verify signature if present
                            if signature:
                                try:
                                    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
                                    c.execute("SELECT pub_pem FROM users WHERE id=?", (owner_id,)); prow = c.fetchone(); conn.close()
                                    owner_pub = prow[0] if prow else None
                                    if owner_pub:
                                        ok = rsa_verify(owner_pub, sha3_rec.encode(), signature)
                                        if ok:
                                            st.success("Signature verification passed — provenance validated.")
                                        else:
                                            st.warning("Signature verification failed.")
                                except Exception:
                                    pass
                            # offer file download (decrypted) — streamlit download button
                            try:
                                st.download_button(label="Download Decrypted File", data=plain, file_name=f"decrypted_{filename}")
                            except Exception:
                                pass
                            # append post-download ledger entry
                            try:
                                ledger_entry = {"event": "download_verify", "user": st.session_state.auth["username"], "filename": filename, "sha3_computed": new_sha3, "tampered": tampered}
                                rec_ledger = append_ledger(ledger_entry)
                                st.json({"ledger_hash": rec_ledger["entry_hash"]})
                            except Exception:
                                pass

# Ledger tab (only present for Admins)
if tab_ledger is not None:
    with tab_ledger:
        st.header("Ledger (append-only)")
        ensure_ledger()
        with open(LEDGER_PATH, "r", encoding="utf-8") as f:
            ledger = json.load(f)

        # Admin sees all entries; non-admins see only entries related to their username
        if user_role == "Admin":
            visible = ledger
        else:
            visible = []
            if username:
                for e in ledger:
                    entry = e.get("entry", {})
                    # check common fields that reference a user
                    if entry.get("owner") == username or entry.get("recipient") == username or entry.get("user") == username:
                        visible.append(e)

        # show up to the most recent 200 visible entries
        idx_start = max(0, len(visible) - 200)
        shown = visible[idx_start:]

        st.write("Visible ledger entries:", len(shown))
        ledger_display = []
        for e in shown:
            ledger_display.append({
                "Timestamp": e.get("timestamp"),
                "Event": e.get("entry", {}).get("event"),
                "Filename": e.get("entry", {}).get("filename"),
                "Ledger Hash": e.get("entry_hash")
            })

        # Render ledger as a table (uses pandas if available, otherwise markdown table)
        render_table(ledger_display, columns=["Timestamp", "Event", "Filename", "Ledger Hash"])

# Admin tab
with tab_admin:
    st.header("Admin / Metadata")
    if st.session_state.auth is None or st.session_state.auth["role"] != "Admin":
        st.warning("Admin role required to view metadata.")
    else:
        # show users
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id, username, role, created_at FROM users")
        users = cur.fetchall()
        conn.close()
        st.subheader("Users")
        render_table([{"id":u[0],"username":u[1],"role":u[2],"created_at":u[3]} for u in users], columns=["id","username","role","created_at"])
        # show files metadata (admins cannot decrypt files)
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT f.id, f.filename, u.username as owner, f.sha3, f.filesize, f.created_at, f.storage_path FROM files f JOIN users u ON f.owner_id=u.id")
        files = cur.fetchall()
        conn.close()
        st.subheader("Files (metadata only)")
        render_table([{"id":r[0],"filename":r[1],"owner":r[2],"sha3":r[3],"filesize":r[4],"created_at":r[5],"storage_path":r[6]} for r in files], columns=["id","filename","owner","sha3","filesize","created_at","storage_path"])
        st.info("Admin can view metadata and ledger but cannot normally decrypt content because private keys are user-held and encrypted by user passwords.")
        st.markdown("---")
        st.subheader("Tamper Alerts")
        # Read ledger and filter tamper_alert events
        try:
            ensure_ledger()
            with open(LEDGER_PATH, "r", encoding="utf-8") as lf:
                full_ledger = json.load(lf)
        except Exception:
            full_ledger = []
        tamper_entries = []
        for e in full_ledger:
            entry = e.get("entry", {})
            if entry.get("event") == "tamper_alert":
                tamper_entries.append({
                    "timestamp": e.get("timestamp"),
                    "file_id": entry.get("file_id"),
                    "filename": entry.get("filename"),
                    "owner": entry.get("owner"),
                    "recorded_sha3": entry.get("recorded_sha3"),
                    "computed_sha3": entry.get("computed_sha3"),
                    "ledger_hash": e.get("entry_hash")
                })
        if tamper_entries:
            render_table(tamper_entries, columns=["timestamp","file_id","filename","owner","recorded_sha3","computed_sha3","ledger_hash"])
        else:
            st.info("No tamper alerts recorded.")

        st.markdown("---")
        st.subheader("Simulate Tamper (local files only)")
        # build options from files list
        file_options = []
        for r in files:
            file_options.append({"id": r[0], "label": f"{r[1]} (owner:{r[2]})", "storage": r[6]})
        if file_options:
            sel_opt = st.selectbox("Select file to tamper", options=file_options, format_func=lambda x: x['label'])
            if st.button("Simulate Tamper"):
                fid = sel_opt['id']
                ok, msg = simulate_tamper(fid)
                if ok:
                    st.success(msg)
                    # append simulation event to ledger for traceability
                    append_ledger({"event": "tamper_simulated", "file_id": fid, "filename": sel_opt['label'], "by": st.session_state.auth['username']})
                else:
                    st.error(msg)
        else:
            st.info("No files available to simulate tamper.")

# Footer / notes: hide Streamlit default footer and remove app caption
st.markdown("""
<style>
footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)
