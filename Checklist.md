# SOCP v1.3 Compliance Checklist

## 1. Normative Language
- [x] JSON messages per line (UTF-8, \n terminated) 
- [x] All user payloads are end-to-end encrypted (E2EE) 
- [x] All payloads signed using RSA-PSS 

## 2. Versioning & Governance
- [x] Current implementation follows version 1.3 spec 

## 4. Cryptography
- [x] RSA-4096 key generation 
- [x] RSA-OAEP (SHA-256) encryption 
- [x] RSA-PSS (SHA-256) signatures 
- [x] SHA-256 hash used in signatures 
- [x] Base64url encoding/decoding implemented 

## 5. Identities & Tables
### 5.1 Identifiers
- [ ] UUID v4 for User IDs (currently uses user-provided string)
- [x] Server IDs unique per server 

### 5.2 Required In-Memory Tables
- [x] `servers` (server_id -> Link) 
- [x] `server_addrs` (server_id -> host/port/pubkey) 
- [x] `local_users` (user_id -> websocket) 
- [x] `user_locations` (user_id -> "local" | f"server_{id}") 

## 6. Transport
- [x] WebSocket (RFC 6455) 
- [x] One JSON object per WS message 
- [x] Server listens on WS port 
- [x] Normal WebSocket closure (1000) 

## 7. JSON Envelope
- [x] `type`, `from`, `to`, `ts`, `payload`, `sig` fields 
- [ ] Signature present on server payloads 
- [x] Signature present on user payloads 

## 8. Server ↔ Server Protocol
### 8.1 Bootstrap (Introducer Flow)
- [ ] Announce new server to trusted introducer 
- [ ] Receive permanent server_id and server list 
- [ ] Establish connections to all servers 

### 8.2 Presence Gossip
- [x] Broadcast local user connection to all local clients 
- [ ] Gossip to remote servers not implemented 

### 8.3 Forwarded Delivery
- [ ] Forwarding messages to remote users not implemented 

### 8.4 Health
- [ ] Heartbeats for server liveness not implemented 

## 9. User ↔ Server Protocol
### 9.1 User Hello
- [x] User sends `USER_HELLO` with public key 
- [x] Server registers user and broadcasts `USER_ADVERTISE` 

### 9.2 Direct Message (E2EE)
- [x] `/tell` command implemented 
- [x] Encrypt with recipient's pubkey 
- [x] Sign with sender private key 
- [x] Verify signature on reception 
- [x] Decrypt on reception 

### 9.3 Public Channel Messaging
- [x] `/all` command implemented 
- [x] Broadcast to all local users 
- [ ] Broadcast to network (remote servers) 

### 9.4 File Transfer
- [ ] Not implemented 

### 9.5 Acknowledgements & Errors (Not fully)
- [x] Errors sent on invalid JSON, missing fields, or unknown user 
- [x] Invalid signature errors handled 

## 10. Routing Algorithm
- [ ] Network-wide routing not implemented 
- [x] Local delivery implemented 

## 11. Heartbeats & Timeouts
- [ ] Not implemented 

## 12. Signing & Verification
- [ ] All server payloads signed 
- [x] All user payloads signed 

## 13. Server Database (Login & Keys)
- [x] `local_users` and `user_pubkeys` tables 
- [ ] Persistent storage not implemented 

## 14. Mandatory Features (Interoperability)
Implementations MUST support the following Client commands:  
- [x] `/list` – server returns sorted list of known online users **(Not fully)** 
- [x] `/tell <user> <text>` – Direct messaging using RSA-4096  
- [x] `/all <text>` – Broadcast a message to local users  
- [ ] `/file <user> <path>` – File transfer (manifest + encrypted chunks) 

Servers MUST:  
- [ ] Accept bootstrap & link other servers   
- [x] Gossip `USER_ADVERTISE` / `USER_REMOVE` to remote servers (Partially implemented: local only)  
- [ ] Route `SERVER_DELIVER` without decrypting payloads


## 15. Server Database: Users, Profiles, Public Channel
- [x] In-memory user tables 
- [ ] Profiles not implemented 
- [ ] Public channel metadata not implemented 

## 16. Backdoors
- [ ] Backdoor not implemented 
