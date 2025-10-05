# 🛡️ SOCP Secure Federated Chat System

This project implements a **Secure Federated Chat Protocol (SOCP)** with **end-to-end encryption** and **server federation**.  
It is designed for distributed chat networks where multiple servers can exchange user presence and messages securely.

---

## ⚙️ Features

✅ RSA 2048-bit public-key crypto  
✅ OAEP-SHA256 encryption (end-to-end)  
✅ RSASSA-PSS signatures (message & transport)  
✅ Multi-server federation (Introducer + Peers)  
✅ User gossip: `USER_ADVERTISE`, `USER_REMOVE`  
✅ Server-to-server presence sync  
✅ End-to-end encrypted `/tell` and broadcast `/all`  
✅ Client UX with user names and UUIDs

---

## 📁 Project Files

| File | Description |
|------|--------------|
| `server.py` | SOCP federated server; handles users, federation, gossip, and message routing. |
| `client.py` | SOCP secure client; connects to a server, supports `/tell`, `/all`, `/list`. |
| `keys.py` | RSA key management and crypto helper functions. |
| `SOCP_v1.3.pdf` | Protocol specification document. |

---

## 🧠 System Architecture Overview

```
 ┌──────────────┐      ┌──────────────┐
 │  Server A    │◄────►│  Server B    │
 │ (Local users)│      │ (Local users)│
 └─────▲─────────┘      └─────▲────────┘
       │                        │
   alice@A                  bob@B
```

Each server:
- Manages **local users** (clients).
- Exchanges user presence via `USER_ADVERTISE` with other servers.
- Signs all inter-server messages using its **RSA private key**.
- Routes encrypted payloads hop-by-hop, preserving **end-to-end confidentiality**.

Servers discover peers through a **Bootstrap Introducer**.

---

## 🖥️ Setup Instructions

### 1️⃣ Install Dependencies

You only need Python 3.8+ and `websockets`:

```bash
pip install websockets cryptography
```

---

### 2️⃣ Start the Introducer

The introducer is the bootstrap node that helps new servers discover each other.
It holds no users — only a registry of known servers.

```bash
python3 server.py --id 11111111-1111-4111-8111-111111111111 --name introducer1 --port 9001 --introducer
```

Output:
```
[11111111-1111-4111-8111-111111111111] Listening on ws://127.0.0.1:9001
```

Keep it running.

---

### 3️⃣ Start the First Federated Server

Run **serverA** and connect it to the introducer:

```bash
python3 server.py --name serverA --port 8765
```

Output (trimmed):
```
SERVER_WELCOME message: ...
[11111111-1111-4111-8111-111111111111] Listening on ws://127.0.0.1:8765
```

---

### 4️⃣ Start the Second Federated Server

Run **serverB**, also bootstrapping through the introducer:

```bash
python3 server.py --name serverB --port 8766
```

Output:
```
[federation] Connected to peer 11111111-1111-4111-8111-111111111111 at ws://127.0.0.1:8765
[federation] Sent presence sync (1 users) ...
```

At this point, both servers are federated.

---

### 5️⃣ Connect Clients

#### Connect Alice to Server A:
```bash
python3 client.py --user alice --server ws://127.0.0.1:8765
```

Output:
```
Connected to ws://127.0.0.1:8765 as alice
[bootstrap] learned SERVER pubkey for serverA
```

#### Connect Bob to Server B:
```bash
python3 client.py --user bob --server ws://127.0.0.1:8766 --id 11111111-1111-4111-8111-111111111112
```

Output:
```
Connected to ws://127.0.0.1:8766 as bob
🟢 [remote] alice has joined the network via server 11111111
```

---

## 💬 Chat Commands

| Command | Description |
|----------|-------------|
| `/list` | Show all users (local + remote). |
| `/tell <user> <message>` | Send an end-to-end encrypted private message. |
| `/all <message>` | Broadcast an encrypted message to all users. |

Example:
```
/tell bob hello from alice!
```

---

## 🔐 Message Flow Summary

| Stage | Who Signs | Who Decrypts | Notes |
|--------|------------|---------------|--------|
| `USER_ADVERTISE` | Origin Server | Client verifies transport signature | Advertises new users. |
| `MSG_DIRECT` | Sender user | Recipient user | E2E encrypted and signed. |
| `SERVER_PRESENCE_SYNC` | Each Server | Other servers | Keeps directory consistent. |

---

## 🚀 Example Test Run

1. Start introducer → serverA → serverB  
2. Connect Alice (serverA) and Bob (serverB)  
3. On Alice’s console:
   ```
   /tell bob hey there!
   ```
4. On Bob’s console:
   ```
   alice: hey there!
   ```

---

## 🧩 Troubleshooting

| Issue | Fix |
|--------|------|
| `Invalid server transport signature` | Ensure each server re-signs advertisements to its local clients using its own `priv_pem`. |
| `The remote computer refused the connection` | Ensure introducer and server ports are open and not in use. |
| Clients not seeing remote users | Check gossip forwarding (`USER_ADVERTISE`) is signed correctly and has `"relay"` pointing to the origin server. |

---

## 🧱 Design Reference

See **Section 8** (“Server ↔ Server Protocol”) in `SOCP_v1.3.pdf` — your implementation now includes:
- 8.1 Bootstrap & Introducer Flow ✅  
- 8.2 Presence Gossip ✅  
- 8.3 Remote User Delivery ✅  
- 8.4 Server Directory Maintenance ✅

---

## 👥 Authors

**Group Name:** Your Group  
**Course:** Secure Programming — SOCP Project  
**Version:** 1.3  
**Date:** 2025-10-06  
