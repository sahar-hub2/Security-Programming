# SOCP Secure Chat — Setup & Run Guide (Phase 2)

This guide explains how to install dependencies and test the secure chat system on **macOS**, **Windows**, or **Linux**.

---

## 🧩 1. Project Files

Make sure your folder contains:

```
client.py
server.py
keys.py
README.md
Checklist.md
```

---

## ⚙️ 2. Requirements

- Python **3.10 – 3.12**
- Internet access only required for first-time dependency install

Check Python version:

```bash
python3 --version
# or on Windows:
python --version
```

If missing:
- **macOS:** `brew install python`
- **Ubuntu/Debian:** `sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip`
- **Windows:** Download & install from [python.org/downloads](https://www.python.org/downloads/) and tick **“Add Python to PATH”**.

---

## 🧱 3. Create a Virtual Environment (recommended)

### 🐚 macOS / Linux
```bash
cd <your-project-folder>
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install websockets cryptography
```

### 💻 Windows PowerShell
```powershell
cd <your-project-folder>
python -m venv .venv
# If blocked, first run:
# Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install websockets cryptography
```

### 🪟 Windows CMD
```cmd
cd <your-project-folder>
python -m venv .venv
.\.venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install websockets cryptography
```

**Deactivate later:**
- macOS/Linux → `deactivate`
- Windows → `deactivate`

---

## 🧩 4. Optional: Install Without venv

If you prefer not to use virtual environments:

### macOS (protected system Python)
```bash
python3 -m pip install --upgrade pip
python3 -m pip install --break-system-packages websockets cryptography
```

### Windows / Linux
```bash
python -m pip install --upgrade pip
pip install websockets cryptography
```

### Alternative (cleaner global install)
```bash
brew install pipx        # macOS
pipx ensurepath
pipx install websockets
pipx install cryptography
```

---

## 🚀 5. Run the Server

Open **Terminal A** (or PowerShell):

```bash
cd <your-project-folder>
# activate venv if using one
python server.py --id S1 --host 127.0.0.1 --port 8765
```

Expected output:
```
[S1] Listening on ws://127.0.0.1:8765
```

> If port 8765 is busy, choose another (e.g. `--port 8888`) and use that in client commands.

---

## 💬 6. Run Two Clients

Open **Terminal B**:
```bash
cd <your-project-folder>
python client.py --user alice --server ws://127.0.0.1:8765
```

Open **Terminal C**:
```bash
cd <your-project-folder>
python client.py --user bob --server ws://127.0.0.1:8765
```

Both should print:
```
Connected to ws://127.0.0.1:8765 as <user>
```

---

## 🧪 7. Test the Features

### 🔹 A. List connected users
In **Alice’s** terminal:
```
/list
```
Expected:
```
Connected users: alice, bob
```

### 🔹 B. Private encrypted message
In **Alice’s** terminal:
```
/tell bob hello bob — this is encrypted
```
Expected on **Bob**:
```
alice: hello bob — this is encrypted
```

### 🔹 C. Broadcast message
In **Bob’s** terminal:
```
/all hello everyone
```
Expected on **Alice**:
```
[all] bob: hello everyone
```

### 🔹 D. Disconnect notice
Press **Ctrl + C** in **Bob**’s window.  
Expected on **Alice**:
```
[server] User bob has disconnected.
```

---

## 🧹 8. Stop Everything Cleanly
- Stop each client with **Ctrl + C**
- Stop the server with **Ctrl + C**

---

## 🧰 9. Platform-Specific Notes

### macOS
- If `cryptography` fails to build:
  ```bash
  xcode-select --install
  ```
- If you see *“externally-managed-environment”* errors → use the venv steps above or add `--break-system-packages`.

### Windows
- Prefer PowerShell with `.venv\Scripts\Activate.ps1`
- If activation blocked:
  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
  ```
- If `ModuleNotFoundError: websockets`, you likely installed packages outside the venv.  
  Activate the venv first, then reinstall with `pip install websockets cryptography`.

### Linux
- Ensure venv support:
  ```bash
  sudo apt-get install -y python3-venv python3-pip
  ```
- Then repeat the macOS/Linux venv steps.

---

## 🧯 10. Troubleshooting

| Issue | Fix |
|-------|-----|
| `ModuleNotFoundError: websockets` | Activate venv, reinstall deps. |
| `OSError: [Errno 48] Address already in use` (macOS) or `Errno 10048` (Windows) | Run server on another port, e.g. `--port 8888`. |
| `cryptography` build errors | Run `xcode-select --install` (macOS) or `sudo apt-get install build-essential` (Linux). |
| Firewall prompt | Allow “Python” network access. |
| Garbled characters | Use plain ASCII text or ensure terminal encoding is UTF-8. |

---

## ✅ 11. What Works (Phase 2 scope)

- WebSocket transport — one JSON object per frame  
- RSA-4096 (OAEP-SHA256) encryption and RSASSA-PSS signatures  
- Server-side transport signatures on relayed payloads  
- Commands: `/tell`, `/all`, `/list`  
- Presence updates (`USER_ADVERTISE`, `USER_REMOVE`)  
- Base64url encoding (no padding) for all binary fields

---

## 🔮 12. Planned Next Steps (optional Phase 3+)

- Persistent key storage (stable identity across restarts)  
- Message ID + timestamp freshness checks (anti-replay)  
- Deduplication / loop suppression  
- Heartbeat + timeout monitoring  
- Encrypted file transfer (`/file` command)

---

## 🧑‍💻 Authors
Your Group Name — Advanced Secure Protocol Design, Implementation and Review (Phase 2)
