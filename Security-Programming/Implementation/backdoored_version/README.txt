============================================================
SOCP Secure Chat System (Vulnerable Version)
============================================================

Course: Secure Programming — Advanced SOCP Project  
Group Name: Project Group 12  
Version: 1.3  
Date: 06 Oct 2025

Authors:
  1. Debasish Saha Pranta (a1963099, debasishsaha.pranta@student.adelaide.edu.au)
  2. Samin Yeasar Seaum (a1976022, saminyeasar.seaum@student.adelaide.edu.au)
  3. Abidul Kabir (a1974976, abidul.kabir@student.adelaide.edu.au)
  4. Sahar Alzahrani (a1938372, sahar.alzahrani@student.adelaide.edu.au)
  5. Mahrin Mahia (a1957342, mahrin.mahia@student.adelaide.edu.au)
  6. Maria Hasan Logno (a1975478, mariahasan.logno@student.adelaide.edu.au)

============================================================
1. PROJECT OVERVIEW
============================================================

The SOCP Secure Chat System is a distributed, end-to-end encrypted chat platform 
implemented in Python. It adheres to the SOCP protocol v1.3, supporting:

  - RSA-4096 (OAEP-SHA256) encryption and RSASSA-PSS signatures
  - End-to-end encrypted private messages (/tell)
  - Broadcast messages (/all)
  - User presence and listing (/list)
  - Point-to-point encrypted file transfer
  - Multi-server federation via introducers
  - Persistent SQLite database for each server

Each server node operates independently with its own keys and persistent database.
Servers discover and federate via trusted Introducers.

NOTE: This submission intentionally contains ethical vulnerabilities for peer review.

============================================================
2. REQUIREMENTS
============================================================

Python 3.10 – 3.12
Dependencies:
    websockets
    cryptography
    sqlite3 (built-in)

Check version:
    python3 --version

============================================================
3. INSTALLATION
============================================================

### A. Create a Virtual Environment (recommended)

macOS / Linux:
    python3 -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip
    pip install websockets cryptography

Windows (PowerShell):
    python -m venv .venv
    .venv\Scripts\Activate.ps1
    pip install --upgrade pip
    pip install websockets cryptography

Deactivate later with:
    deactivate

============================================================
4. DIRECTORY STRUCTURE
============================================================

After setup, your folder should include:

    client.py
    server.py
    keys.py
    datavault.py
    README.txt
    introducers.yaml  (auto-generated)
    .keys/            (key storage)
    data_vault.sqlite (created automatically)

============================================================
5. INTRODUCER SETUP (Server ↔ Server Bootstrap)
============================================================

Introducers act as trusted bootstrap servers that assign IDs to new nodes.

1. Generate introducer keys and config:
    python3 gen_introducer_keys.py

   This creates:
      .keys/
         introA.priv.pem / introA.pub.pem
         introB.priv.pem / introB.pub.pem
         introC.priv.pem / introC.pub.pem
      introducers.yaml

2. Run introducers in three terminals:

    python3 server.py --name introA --port 9001 --introducer
    python3 server.py --name introB --port 9002 --introducer
    python3 server.py --name introC --port 9003 --introducer

Expected output:
    [introA] Listening on ws://127.0.0.1:9001
    [bootstrap] OK via ws://127.0.0.1:9001 → assigned_id=11111111-...

============================================================
6. RUNNING A REGULAR SERVER
============================================================

After introducers are online, start a normal server:

    python3 server.py --name serverA --port 8765

Example Output:
    [vault] SQLite database initialised and public channel ready.
    [serverA] Listening on ws://127.0.0.1:8765

Each server creates its own persistent data_vault.sqlite file.

To check database content:
    sqlite3 data_vault.sqlite
    sqlite> .headers on
    sqlite> .mode column
    sqlite> SELECT * FROM users;

============================================================
7. RUNNING CLIENTS
============================================================

Open a new terminal for each client.

Example:

Terminal 1:
    python3 client.py --user alice --server ws://127.0.0.1:8765

Terminal 2:
    python3 client.py --user bob --server ws://127.0.0.1:8765

Expected output:
    Connected to ws://127.0.0.1:8765 as alice (id=...)

============================================================
8. CHAT COMMANDS
============================================================

/list
    Lists all currently connected users.

Example:
    Connected users: alice, bob

/tell <name|uuid> <message>
    Sends an encrypted private message to a specific user.

Example:
    /tell bob hey, this is encrypted

/all <message>
    Sends an encrypted message to all connected users.

Example:
    /all hello everyone

/sendfile <user> <path>
    Sends an encrypted file (split and OAEP-encrypted per chunk).

/quit
    Gracefully disconnects.

============================================================
9. EXPECTED BEHAVIOUR
============================================================

When Alice sends:
    /tell bob hello

Bob sees:
    alice: hello

When Bob sends:
    /all hi everyone

Alice sees:
    [all] bob: hi everyone

When Bob disconnects:
    [server] User bob has disconnected.

============================================================
10. DATABASE PERSISTENCE
============================================================

Each server maintains its own SQLite database: `data_vault.sqlite`

Tables:
  users(user_id, pubkey, privkey_store, pake_password, meta, version)
  groups(group_id, creator_id, created_at, meta, version)
  group_members(group_id, member_id, role, wrapped_key, added_at)

To inspect:
    sqlite3 data_vault.sqlite
    sqlite> .tables
    sqlite> SELECT user_id, json_extract(meta,'$.display_name') AS name FROM users;

============================================================
11. TROUBLESHOOTING
============================================================

Common issues:

* Address in use:
    Run server on another port:  python3 server.py --name serverA --port 8888

* ModuleNotFoundError:
    Activate venv first and reinstall dependencies.

* Permission denied (Windows PowerShell):
    Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

* cryptography build errors (macOS/Linux):
    xcode-select --install
    or
    sudo apt install build-essential

============================================================
12. ETHICAL VULNERABILITIES
============================================================

This version is intentionally "vulnerable" for peer review.

The vulnerabilities are within the boundaries of the chat system and 
may include (conceptually):
  - Improper signature verification or missing authentication edge cases
  - Weak persistence of cryptographic material
  - Logic flaws in message routing or timestamp freshness
  - Minor key reuse or TOFU (Trust-On-First-Use) reliance

They do NOT access, modify, or exfiltrate any external data.  
They exist solely for controlled academic testing.

============================================================
13. TEST PLAN OVERVIEW
============================================================

Test setup:
  1. Run 3 introducers (ports 9001–9003)
  2. Run one regular server (port 8765)
  3. Connect 2 clients (alice, bob)
  4. Test /list, /tell, /all
  5. Test file transfer:
        /sendfile bob test.txt
  6. Observe persistent database entries:
        sqlite3 data_vault.sqlite → SELECT * FROM users;
  7. Stop with Ctrl + C.

============================================================
14. CONTACT
============================================================

Group 12 — Secure Programming (Semester 2, 2025)
University of Adelaide  
For review and feedback coordination, contact any member listed above.

============================================================
END OF README.TXT
============================================================
