# 🛡️ Secure Overlay Chat Protocol (SOCP)
Version: 1.3 – Federated Secure Chat (Updated 23-10-2025)</br>
Scope: Class-wide standard.

## Overview
SOCP 1.3 implements a federated end-to-end encrypted chat network.
Each user connects to a local server; servers exchange signed presence and messages through a trusted introducer.
Every payload is cryptographically signed and encrypted.

## Key features
* End-to-end encryption (RSA-OAEP + SHA-256).
* Digital signatures (RSA-PSS + SHA-256) for message authenticity.
* Secure federation via introducer announcement channel.
* Dynamic user advertisement and revocation between servers.
* Command-driven CLI client (/tell, /all, /list, /sendfile, /quit).
* Full cryptographic key persistence between sessions.
* Optional sandboxed “backdoored_version/”.

## SOCP Compliance
This implementation conforms to SOCP v1.3 (Protocol Freeze: 17-09-2025).  
Implemented mandatory features include:
- RSA-4096 encryption (RSA-OAEP, SHA-256)
- RSASSA-PSS signatures for message integrity
- End-to-end encrypted direct messages (E2EE)
- Server ↔ Server gossip for presence updates
- Bootstrap introducer flow for network join
- Public channel broadcasting and key distribution
- Canonical JSON envelope format (one per WebSocket message)

## Architecture Overview
```

                   ┌──────────────────────────┐
                   │        Introducer        │
                   │ (user advertisements +   │
                   │  federation directory)   │
                   └────────────┬─────────────┘
                                │
        ┌───────────────────────┼────────────────────────┐
        │                       │                        │
┌──────────────┐       ┌────────────────┐        ┌────────────────┐
│  Server A    │◄─────►│   Server B     │◄──────►│   Server C     │
│ Local Users  │       │ Local Users    │        │ Local Users    │
└──────────────┘       └────────────────┘        └────────────────┘
        │                        │                         │
     alice                    bob, carol                 dave
```
* Introducer: maintains a live registry of known servers and users; all communications are signed.
* Servers: verify incoming signatures, enforce local access control, and relay encrypted payloads.
* Clients: hold private keys; only clients can decrypt or sign messages.

## Security Model
* Encryption — Messages are encrypted with the recipient’s RSA public key using RSA-OAEP (SHA-256).
* Integrity — All messages are signed with RSA-PSS (SHA-256).
* Verification — Servers verify signatures before routing.
* Privacy — Servers cannot decrypt user payloads.
* Replay Protection (Phase 3 planned) — Timestamp + nonce validation.

## Project Structure
```
Security-Programming/
│
├── Documentation/
│   ├── Developer Setup Guide (Phase 2).md   # Archived: Secure Overlay Chat Protocol overview
│   ├── SCOP.pdf                             # Standard protocol agreement / reference document
│   └── Reflection_Report/                   # Team reflection and lessons learned
│      ├── Reflective Commentary.pdf         # General reflection: protocols, AI used, testing, peer review, member contributions
│      └── Appendix/                         # Supporting documents
│         ├── BACKDOOR_README(PoC).md
│         ├── Peer_Review/                   # Holding for both received and given peer reviews
│         └── Testing Report.pdf             # Testing approach and evidence
│
├── Implementation/
│   ├── secure_version/                      # Secure implementation (production-ready)
│   │   ├── client.py                        # Client application (connects to server)
│   │   ├── server.py                        # Main server program handling connections
│   │   ├── keys.py                          # Key generation and management logic
│   │   ├── datavault.py                     # Local encrypted data storage and retrieval
│   │   ├── gen_introducer_keys.py           # Utility to generate introducer (server) keys
│   │   ├── introducers.yaml                 # Introducer list (server discovery info)
│   │   ├── requirements.txt                 # Python dependencies
│   │   ├── data_vault.sqlite                # SQLite database file
│   │   ├── data_vault.sqlite-shm            # SQLite shared memory file
│   │   ├── data_vault.sqlite-wal            # SQLite write-ahead log
│   │   ├── downloads/                       # Folder for downloaded files
│   │   └── __pycache__/                     # Compiled Python bytecode cache
│
│   ├── backdoored_version/                  # Insecure / vulnerable version
│   │   └── ...                              # Same structure as secure_version but with flaws
│
├── Testing/
│   ├── test_cases/
│   │   ├── test_client.py                   # Tests for client-side behavior
│   │   ├── test_server.py                   # Tests for server-side operations
│   │   ├── test_keys.py                     # Tests for key handling and persistence
│   │   ├── test_integration.py              # Full integration tests (end-to-end)
│   │   ├── test_security_hardening.py       # Security hardening tests for secure_version
│   │   └── __pycache__/                     # Cached test bytecode
│
└── README.md                                # Entry point (this file)


```
# ⚙️ Setup & Installation
## Requirements
- Python 3.11+ recommended.
- Linux/Ubuntu dev container (this workspace uses Ubuntu 24.04.2 LTS).
- Install dependencies via `requirements.txt`:
   - pytest
   - pytest-asyncio
   - websockets
   - pyyaml
   - cryptography
     
```bash
# from Implementation/secure_version/
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Setup Instructions
**1. Navigate to the Project Directory:**
```bash
cd Security-Programming
```
**2. Create and Activate a Virtual Environment:**
macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```
Windows (PowerShell):
```bash
python -m venv venv
venv\Scripts\activate
```
**3. Install Dependencies:**
```bash
python -m pip install --upgrade pip
python -m pip install -r Implementation/secure_version/requirements.txt
```
**4. Generate keys** </br>
Before the first run, generate the introducer’s RSA keys and configuration file:
```
cd Implementation/secure_version
python gen_introducer_keys.py
```

## Run Instructions

**1. Start the Introducer**
```bash
cd Implementation/secure_version
python3 server.py --id 11111111-1111-4111-8111-111111111111 --name introducer1 --port 9001 --introducer
```
Expected output:
```
loaded existing keys
[keys] Loaded keys for introducer1 → .keys/introducer1.priv.pem / .pub.pem
[vault] SQLite database initialised and public channel ready.
[11111111-1111-4111-8111-111111111111] Listening on ws://127.0.0.1:9001
```

**2. Start Server A and Server B**

```bash
cd Implementation/secure_version
python3 server.py --name serverA --port 8764
python3 server.py --name serverB --port 8765
```
Expected output:
```
loaded existing keys
[keys] Loaded keys for serverA → .keys/serverA.priv.pem / .pub.pem
[bootstrap] OK via ws://127.0.0.1:9001 → assigned_id=53e96a0e-f124-4013-a0e9-f5e8df110b9b
[bootstrap] Using server ID: 53e96a0e-f124-4013-a0e9-f5e8df110b9b
[vault] SQLite database initialised and public channel ready.
[53e96a0e-f124-4013-a0e9-f5e8df110b9b] Listening on ws://127.0.0.1:8764
```
**3. Start Clients**
```bash
cd Implementation/secure_version
python3 client.py --user alice --server ws://127.0.0.1:8764 
python3 client.py --user bob --server ws://127.0.0.1:8765
```
Expected output:
```
loaded existing keys
Connected to ws://127.0.0.1:8764 as alice (id=ee5966e5-e61d-40e0-a398-6ce2b807931d)
[bootstrap] learned SERVER pubkey for serverA (53e96a0e-f124-4013-a0e9-f5e8df110b9b)
```
Once connected, each server advertises its local users to others through the introducer.

## Example Scenario
**Step 1: List active users**</br>
On Alice’s terminal:
```
/list
```
Expected output:
```
Connected users:
- bob (ce4732e1-fc12-4c62-a89a-74d5a915b93d)
```
**Step 2: Send an encrypted message**
```
/tell bob Hello Bob, this is a secure message!
```
Alice’s client:
* Encrypts with Bob’s public key (RSA-OAEP, SHA-256).
* Signs message with Alice’s private key (RSA-PSS, SHA-256).
* Sends to Server A → Introducer → Server B. </br>
Bob’s client decrypts and displays:
```
alice (ee5966e5-e61d-40e0-a398-6ce2b807931d): Hello Bob, this chat is secure!
```
Supported commands: /tell, /all, /list, /sendfile, /quit

## Troubleshooting
| Issue                       | Cause                            | Fix                                             |
| --------------------------- | -------------------------------- | ----------------------------------------------- |
| `Address already in use`    | Port conflict                    | Change `--port` argument                        |
| `cryptography build failed` | Missing system headers           | macOS: `brew install openssl` → re-install deps |
| `Connection refused`        | Server not started or wrong port | Verify introducer + server ports match          |
| `UnicodeDecodeError `         | Non-UTF8 payload                 | Delete old keys and restart                     |
| `“No active users”` shown     | Introducer not reachable         | Ensure introducer is running first              |


## Testing
To verify that the system functions correctly, you can run all automated tests using pytest.</br>
These tests cover individual modules (client.py, server.py, keys.py) as well as end-to-end message exchange.


### Run All Tests
From the root directory:
```bash
pytest -v
```
**Note:** Ensure that all required dependencies and environment variables are properly set up before running the tests.

## Backdoor Disclaimer
The `backdoored_version/` directory is provided for educational and testing purposes only.</br>
It intentionally includes insecure patterns to illustrate common vulnerabilities; it is not intended for production use and should be run only in isolated, controlled environments.</br>
For demonstrations or any live testing, we recommend using the `secure_version/` implementation.


## Author: 
Developed by group 12 for the University of Adelaide Security Programming course, 2025.

**MEMBERS:**  
  1. Debasish Saha Pranta (a1963099, debasishsaha.pranta@student.adelaide.edu.au)
  2. Samin Yeasar Seaum (a1976022, saminyeasar.seaum@student.adelaide.edu.au)
  3. Abidul Kabir (a1974976, abidul.kabir@student.adelaide.edu.au)
  4. Sahar Alzahrani (a1938372, sahar.alzahrani@student.adelaide.edu.au)
  5. Mahrin Mahia (a1957342, mahrin.mahia@student.adelaide.edu.au)
  6. Maria Hasan Logno (a1975478, mariahasan.logno@student.adelaide.edu.au)



