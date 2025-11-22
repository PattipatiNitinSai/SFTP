1) Create venv:
        python -m venv .venv

   - On Windows (PowerShell):
           .\.venv\Scripts\Activate.ps1

   - On Windows (Command Prompt):
           .\.venv\Scripts\activate.bat

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
