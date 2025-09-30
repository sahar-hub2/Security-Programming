# Copilot Instructions for Security-Programming

## Project Overview
This project is a secure messaging system using Python and WebSockets. It consists of a server (`server.py`) and client (`client.py`) that communicate using signed and encrypted messages. RSA cryptography is used for key generation, message encryption, and signature verification (see `keys.py`).

## Architecture & Data Flow
- **Server (`server.py`)**: Accepts WebSocket connections from clients. Manages user registration, public key advertisement, direct messaging, broadcast messaging, and user disconnects. All messages are signed using RSA-PSS and encoded with base64url.
- **Client (`client.py`)**: Connects to the server, generates its own RSA keypair, registers with the server, and can send direct or broadcast messages. Direct messages are encrypted with the recipient's public key and signed by the sender.
- **Key Management (`keys.py`)**: Provides functions for RSA key generation, encryption/decryption, signing, and verification. All keys are exchanged in PEM format.

## Message Types & Protocol
- `USER_HELLO`: Client registration, sends public key to server.
- `USER_ADVERTISE`: Server broadcasts public keys of connected users.
- `MSG_DIRECT`: Direct encrypted message between users, includes ciphertext and signature.
- `MSG_BROADCAST`: Plaintext broadcast to all users.
- `CMD_LIST` / `CMD_LIST_RESULT`: List connected users.
- `USER_REMOVE`: Notifies clients of user disconnects.
- All messages include a `sig` field: base64url-encoded RSA-PSS signature of the payload.

## Developer Workflows
- **Install dependencies:**
  ```bash
  pip install websockets cryptography
  ```
- **Run server:**
  ```bash
  python server.py --id <server_id> [--host 127.0.0.1] [--port 8765]
  ```
- **Run client:**
  ```bash
  python client.py --user <username> --server ws://127.0.0.1:8765
  ```
- **Commit workflow:**
  ```bash
  git add .
  git commit -m "Describe your changes"
  git push origin main
  ```

## Project-Specific Patterns
- All cryptographic operations use 4096-bit RSA keys and SHA-256.
- Public keys are exchanged and stored in PEM format.
- Message signatures are always calculated over the sorted JSON payload and encoded with base64url.
- Direct messages are encrypted and signed; broadcast messages are plaintext but signed.
- Usernames must be unique per server instance.
- All protocol logic is implemented in `server.py` and `client.py` (no external protocol libraries).

## Integration Points
- Relies on `websockets` and `cryptography` Python packages.
- No persistent storage; all state is in-memory.
- No external services or databases.

## Example: Direct Message Flow
1. Alice sends `/tell Bob hi` in client.
2. Client encrypts "hi" with Bob's public key, signs ciphertext, sends `MSG_DIRECT`.
3. Server relays to Bob, signing the payload.
4. Bob's client verifies signature, decrypts message, displays plaintext.

## Key Files
- `server.py`: WebSocket server, protocol logic
- `client.py`: Client logic, user interaction
- `keys.py`: Cryptographic utilities

---
**If any workflows are unclear, please ask for clarification or provide feedback to improve these instructions.**
