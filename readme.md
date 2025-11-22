1) Create venv:
        python -m venv .venv

   - On Windows (PowerShell):
           .\.venv\Scripts\Activate.ps1

   - On Windows (Command Prompt):
           .\.venv\Scripts\activate.bat
           .\.venv\Scripts\Activate.ps1

   - On macOS / Linux:
           source .venv/bin/activate

2) Install deps:
          python -m pip install -U pip wheel
          # from requirements.txt (recommended)
          python -m pip install -r requirements.txt
          # or install individually
          python -m pip install streamlit==1.24.0 cryptography pillow paramiko pyopenssl six

3) Launch app:
          streamlit run app.py
1) Create and activate a virtual environment

PowerShell (Windows):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Command Prompt (Windows):
```bat
python -m venv .venv
.\.venv\Scripts\activate.bat
```

macOS / Linux:
```bash
python -m venv .venv
source .venv/bin/activate
```

2) Install dependencies

Recommended (from `requirements.txt`):
```powershell
python -m pip install -U pip wheel
python -m pip install -r requirements.txt
```

If you prefer to install packages individually:
```powershell
python -m pip install streamlit cryptography pillow paramiko pyopenssl six
```

3) Run the Streamlit app

From the project root (after activating the venv):
```powershell
streamlit run app.py
```

4) (Optional) Run a local Docker SFTP server for testing

This project was tested with a simple SFTP container. The commands below start an SFTP server that exposes port `2222` on the host and mounts a local folder for uploaded files.

PowerShell commands (run from a directory where you want the SFTP server's data to live):
```powershell
# create a folder for the SFTP server's files
mkdir sftp_data
# pull and run an sftp container (atmoz/sftp)
# user: foo, password: pass, share the host folder ./sftp_data as /home/foo/uploads in the container
docker run --rm -p 2222:22 -v ${PWD}/sftp_data:/home/foo/uploads:delegated -d atmoz/sftp foo:pass:1001
```

Notes:
- The `atmoz/sftp` image creates a user `foo` with password `pass` in the example above. Adjust username/password as needed.
- The container maps host `sftp_data` to the user's home `uploads` directory. Files uploaded by the app to `uploads/` will appear in that folder on the host.

Prepare SSH keys for the SFTP container (save keys into `sftp_data`)

If you want to use key-auth for the `atmoz/sftp` test container, generate the keypair directly into the `sftp_data` folder so the container can use it as the user's home directory.

PowerShell example (generate keys into `sftp_data\.ssh`):
```powershell
# make folders
mkdir sftp_data
mkdir sftp_data\.ssh

# RSA (common):
ssh-keygen -t rsa -b 4096 -f .\sftp_data\.ssh\id_rsa_example -C "example key"

# Ed25519 (modern):
ssh-keygen -t ed25519 -f .\sftp_data\.ssh\id_ed25519_example -C "example key"

# append the public key(s) to authorized_keys (so the container user will accept them)
Get-Content .\sftp_data\.ssh\id_rsa_example.pub | Out-File -FilePath .\sftp_data\.ssh\authorized_keys -Encoding ascii -Append
# or using type/>> on Windows
type .\sftp_data\.ssh\id_rsa_example.pub >> .\sftp_data\.ssh\authorized_keys
```

Linux / macOS example:
```bash
mkdir -p sftp_data/.ssh
ssh-keygen -t rsa -b 4096 -f ./sftp_data/.ssh/id_rsa_example -C "example key"
ssh-keygen -t ed25519 -f ./sftp_data/.ssh/id_ed25519_example -C "example key"
cat ./sftp_data/.ssh/id_rsa_example.pub >> ./sftp_data/.ssh/authorized_keys
chown -R $(id -u):$(id -g) sftp_data/.ssh || true
chmod 700 sftp_data/.ssh || true
chmod 600 sftp_data/.ssh/authorized_keys || true
```

Run the container mounting `sftp_data` as the user's home so `authorized_keys` is respected:
```powershell
docker run --rm -p 2222:22 -v ${PWD}/sftp_data:/home/foo:delegated -d atmoz/sftp foo:1001:1001
```

Notes:
- When the container's `/home/foo/.ssh/authorized_keys` contains your public key, SSH key authentication will succeed for user `foo`.
- Be careful with file permissions on Linux; the SSH server may reject keys if permissions are too open.

5) Running the project's reset/inspection scripts

- To safely wipe app runtime state (database, ledger, storage), use `reset_project.py` (it asks for confirmation):
```powershell
python reset_project.py
# or non-interactive
python reset_project.py --yes
```

- To inspect the latest ledger/db record (debug helper):
```powershell
python inspect_latest.py
```

6) Troubleshooting

- If you see errors about missing `six.moves` or similar during Streamlit startup, install `six`:
```powershell
pip install six
```

- If Streamlit tries to import `pandas` and your environment lacks binary wheels for your Python version, either install `pandas` (`pip install pandas`) or ensure displays render via `st.text`/`st.write` (the app renders lightweight JSON if pandas is unavailable).

7) Security notes

- This repository is a prototype/demonstration. For production use do not store private keys unencrypted, use KMS/HSM for key wrapping, enable TLS on all connections, and harden the SFTP server and database access.

If you want, I can add a Docker Compose file that runs the SFTP container and the app together for local testing — tell me and I'll scaffold it.
