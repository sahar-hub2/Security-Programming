"""
client.py
----------
SOCP client for secure chat communication.

Implements:
- RSA-based end-to-end encryption (OAEP-SHA256)
- RSASSA-PSS message signatures (SHA-256)
- Base64url encoding (no padding)
- Commands: /tell, /all (E2EE fan-out), /list
- Handles USER_ADVERTISE, USER_REMOVE, MSG_DIRECT, MSG_BROADCAST
- Nice UX: show names with UUIDs; allow /tell <name> as well as /tell <uuid>

Author: Your Group Name
"""

import asyncio, websockets, json, argparse, time, uuid, re
from keys import (
    load_or_create_keys,
    rsa_oaep_encrypt,
    rsa_oaep_decrypt,
    rsa_pss_sign,
    rsa_pss_verify,
    b64url_encode,
    b64url_decode,
    public_pem_to_der_b64url,
    der_b64url_to_public_pem,
    load_or_create_user_uuid,
)

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def now_ms() -> int:
    """Return the current UNIX timestamp in milliseconds."""
    return int(time.time() * 1000)

def verify_transport_sig(msg: dict, known_pubkeys: dict) -> bool:
    """
    Verify the server's transport signature over msg['payload'].
    - Prefer msg['relay'] (server that relayed/signed).
    - Fallback to msg['from'] when from==server_id (e.g., USER_ADVERTISE or CMD_LIST_RESULT).
    """
    sig_b64u = msg.get("sig")
    if not sig_b64u:
        return True  # tolerate missing while developing
    signer_id = msg.get("relay") or msg.get("from")
    if signer_id not in known_pubkeys:
        print(f"unknown pub key")
        return False
    payload_bytes = json.dumps(msg.get("payload", {}), sort_keys=True).encode()
    try:
        return rsa_pss_verify(known_pubkeys[signer_id], payload_bytes, b64url_decode(sig_b64u))
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Main async client function
# ---------------------------------------------------------------------------

async def run_client(nickname: str, server_url: str):
    """
    Launch a single client instance that connects to a SOCP server,
    performs registration, and handles bidirectional message flow.
    """
    # Resolve a UUID v4 identity for this nickname (on-wire identity)
    proto_id = load_or_create_user_uuid(nickname)

    # Load (or create) a persistent RSA-4096 keypair for this user (by nickname)
    priv_pem, pub_pem = load_or_create_keys(nickname)

    # Known keys and names
    known_pubkeys: dict[str, bytes] = {}     # uuid -> PEM
    id_to_name: dict[str, str] = {}          # uuid -> display name
    name_index: dict[str, str] = {}          # lower(name) -> uuid

    def remember_name(uid: str, name: str | None):
        dn = (name or uid).strip()
        id_to_name[uid] = dn
        # only index non-empty names
        if name:
            name_index[name.lower()] = uid

    def display(uid: str) -> str:
        n = id_to_name.get(uid)
        return f"{n} ({uid})" if n and n != uid else uid

    # Establish WebSocket connection to the target SOCP server
    async with websockets.connect(server_url, ping_interval=15, ping_timeout=45) as ws:
        # --- 1. Registration handshake -------------------------------------
        await ws.send(json.dumps({
            "type": "USER_HELLO",
            "from": proto_id,  # MUST be UUID v4
            "to": "*",
            "id": uuid.uuid4().hex,
            "ts": now_ms(),
            "payload": {
                "pubkey_b64u": public_pem_to_der_b64url(pub_pem),
                "name": nickname,  # human-friendly name for UX
            },
        }))
        print(f"Connected to {server_url} as {nickname} (id={proto_id})")

        # -------------------------------------------------------------------
        # Inner coroutine: handles outgoing messages (user input -> send)
        # -------------------------------------------------------------------
        async def sender():
            while True:
                try:
                    line = await asyncio.get_event_loop().run_in_executor(None, input)
                except (EOFError, KeyboardInterrupt):
                    break

                # -------------------- Private Message (/tell) ----------------
                if line.startswith("/tell "):
                    parts = line.split(" ", 2)
                    if len(parts) < 3:
                        print("Usage: /tell <user_uuid|name> <message>")
                        continue
                    target_raw, msg_text = parts[1], parts[2]

                    # Resolve target: prefer UUID, else by (case-insensitive) name
                    if target_raw in known_pubkeys:
                        target = target_raw
                    elif UUID_RE.match(target_raw):
                        target = target_raw
                        if target not in known_pubkeys:
                            print(f"No public key for {target}, cannot send encrypted message.")
                            continue
                    else:
                        looked = name_index.get(target_raw.lower())
                        if not looked:
                            print(f"Unknown recipient '{target_raw}'. Try /list.")
                            continue
                        target = looked

                    # Encrypt with recipient’s public key
                    ciphertext = rsa_oaep_encrypt(known_pubkeys[target], msg_text.encode())

                    # Build payload
                    payload = {
                        "ciphertext": b64url_encode(ciphertext),
                        "sender_pub": public_pem_to_der_b64url(pub_pem),
                        "content_sig": b64url_encode(rsa_pss_sign(priv_pem, ciphertext)),  # sign ciphertext itself
                    }

                    # Add user's envelope signature (usig) over payload
                    usig_bytes = rsa_pss_sign(priv_pem, json.dumps(payload, sort_keys=True).encode())
                    usig_b64u = b64url_encode(usig_bytes)

                    # Build final message frame
                    msg = {
                        "type": "MSG_DIRECT",
                        "from": proto_id,
                        "to": target,
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "payload": payload,
                        "usig": usig_b64u,
                    }

                    await ws.send(json.dumps(msg))


                # -------------------- List Connected Users (/list) ------------
                elif line.strip() == "/list":
                    await ws.send(json.dumps({
                        "type": "CMD_LIST",
                        "from": proto_id,
                        "to": "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms()
                    }))
                
                elif line.strip() == "/quit":
                    await ws.close(code=1000, reason="Client requested")
                    return

                # -------------------- Broadcast Message (/all) ----------------
                # SOCP §1 & §4 require E2EE + signatures for user content.
                # We implement fan-out: per-recipient MSG_DIRECT, each encrypted+signed.
                elif line.startswith("/all "):
                    msg_text = line[len("/all "):]
                    targets = [uid for uid in known_pubkeys.keys() if uid != proto_id]
                    if not targets:
                        print("[all] No known recipients yet; wait for advertisements or /list.")
                        continue
                    for target in targets:
                        try:
                            ciphertext = rsa_oaep_encrypt(known_pubkeys[target], msg_text.encode())

                            payload = {
                                "ciphertext": b64url_encode(ciphertext),
                                "sender_pub": public_pem_to_der_b64url(pub_pem),
                                "content_sig": b64url_encode(rsa_pss_sign(priv_pem, ciphertext)),
                            }

                            usig_bytes = rsa_pss_sign(priv_pem, json.dumps(payload, sort_keys=True).encode())
                            usig_b64u = b64url_encode(usig_bytes)

                            msg = {
                                "type": "MSG_DIRECT",
                                "from": proto_id,
                                "to": target,
                                "id": uuid.uuid4().hex,
                                "ts": now_ms(),
                                "payload": payload,
                                "usig": usig_b64u,
                            }

                            await ws.send(json.dumps(msg))
                        except Exception as e:
                            print(f"[all] Failed to send to {display(target)}: {e}")


        # -------------------------------------------------------------------
        # Inner coroutine: handles incoming messages (receive -> display)
        # -------------------------------------------------------------------
        async def receiver():
            # Buffer for adverts received before we know the server key
            pending_advertises = []

            try:
                async for raw in ws:
                    msg = json.loads(raw)
                    mtype = msg.get("type")

                    # ---------- Receive a USER_ADVERTISE ---------------------
                    if mtype == "USER_ADVERTISE":
                        print(f"client user advertise: {msg}")
                        # Ignore malformed or inter-server gossip frames
                        if "user_id" in msg.get("payload", {}):
                            # This is a gossip USER_ADVERTISE (server↔server format), not client-facing
                            print("[debug] Skipping inter-server USER_ADVERTISE frame")
                            continue

                        
                        payload = msg.get("payload", {})
                        uid = payload.get("user")
                        pubkey_b64u = payload.get("pubkey_b64u")
                        name = payload.get("name")
                        relay = msg.get("relay") or msg.get("from")
                        if not uid or not pubkey_b64u:
                            continue

                        # Bootstrap TOFU: accept server's own key once
                        if relay not in known_pubkeys:
                            if uid == relay:
                                known_pubkeys[uid] = der_b64url_to_public_pem(pubkey_b64u)
                                remember_name(uid, name)
                                print(f"[bootstrap] learned SERVER pubkey for {display(uid)}")
                                # Process buffered adverts if any
                                for pend in list(pending_advertises):
                                    if verify_transport_sig(pend, known_pubkeys):
                                        p = pend["payload"]
                                        puid = p["user"]
                                        known_pubkeys[puid] = der_b64url_to_public_pem(p["pubkey_b64u"])
                                        remember_name(puid, p.get("name"))
                                        print(f"[server] learned pubkey for {display(puid)}")
                                pending_advertises.clear()
                                continue
                            else:
                                # Buffer adverts until we know the server key
                                pending_advertises.append(msg)
                                continue

                        # Normal path: verify transport sig and store key
                        if not verify_transport_sig(msg, known_pubkeys):
                            print("[SECURITY] Invalid server transport signature on USER_ADVERTISE.")
                            continue

                        # Store user key
                        known_pubkeys[uid] = der_b64url_to_public_pem(pubkey_b64u)
                        remember_name(uid, name)

                        # ✅ NEW FEATURE: show message when a new user joins remotely
                        server_origin = msg.get("relay")
                        if server_origin and server_origin != uid:
                            print(f"🟢 [remote] {display(uid)} has joined the network via server {server_origin[:8]}")
                        else:
                            print(f"🟢 [local] {display(uid)} is now online")

                        print(f"[server] learned pubkey for {display(uid)}")

                    # ---------- Receive a direct encrypted message -----------
                    elif mtype == "MSG_DIRECT":
                        if not verify_transport_sig(msg, known_pubkeys):
                            print("[SECURITY] Invalid server transport signature.")
                            continue
                        payload = msg.get("payload", {})
                        ciphertext_b64u = payload.get("ciphertext")
                        signature_b64u  = payload.get("content_sig")
                        sender_uid = msg.get("from")

                        if not ciphertext_b64u or not signature_b64u:
                            print(f"[recv] Invalid message from {display(sender_uid)}")
                            continue
                        if sender_uid not in known_pubkeys:
                            print(f"Message from {display(sender_uid)}, but no pubkey known.")
                            continue

                        ciphertext = b64url_decode(ciphertext_b64u)
                        signature  = b64url_decode(signature_b64u)

                        if not rsa_pss_verify(known_pubkeys[sender_uid], ciphertext, signature):
                            print(f"[SECURITY] Invalid signature from {display(sender_uid)}!")
                            continue

                        plaintext = rsa_oaep_decrypt(priv_pem, ciphertext).decode()
                        print(f"{display(sender_uid)}: {plaintext}")

                    # ---------- Handle USER_REMOVE (disconnection) ------------
                    elif mtype == "USER_REMOVE":
                        if not verify_transport_sig(msg, known_pubkeys):
                            print("[SECURITY] Invalid server transport signature.")
                            continue
                        payload = msg.get("payload", {})
                        removed_user = payload.get("user")
                        nm  = payload.get("name")
                        if removed_user:
                            known_pubkeys.pop(removed_user, None)
                            n = id_to_name.pop(removed_user, None)
                            if n:
                                name_index.pop(n.lower(), None)
                            print(f"[server] User {nm} ({removed_user}) has disconnected.")

                    # ---------- Handle broadcast messages (system notices) ----
                    elif mtype == "MSG_BROADCAST":
                        if not verify_transport_sig(msg, known_pubkeys):
                            print("[SECURITY] Invalid server transport signature.")
                            continue
                        payload = msg.get("payload", {})
                        text = payload.get("text")
                        sender_uid = msg.get("from")
                        if text:
                            print(f"[all] {display(sender_uid)}: {text}")

                    # ---------- Handle user list result -----------------------
                    elif mtype == "CMD_LIST_RESULT":
                        if not verify_transport_sig(msg, known_pubkeys):
                            print("[SECURITY] Invalid server transport signature.")
                            continue
                        payload = msg.get("payload", {}) or {}
                        users = payload.get("users", [])
                        names = payload.get("names", {})
                        # merge names into our index
                        for uid in users:
                            if uid in names:
                                remember_name(uid, names[uid])
                        # Display friendly list
                        pretty = ", ".join([display(uid) for uid in users]) if users else "(none)"
                        print(f"Connected users: {pretty}")
                    
                    elif mtype == "USER_DELIVER":
                        if not verify_transport_sig(msg, known_pubkeys):
                            print("[SECURITY] Invalid server transport signature on USER_DELIVER.")
                            continue
                        
                        print(f"user deliver payload: [{msg}]")
                        payload = msg.get("payload", {})
                        ciphertext_b64u = payload.get("ciphertext")
                        sender_uid = payload.get("sender")
                        sender_pub_b64u = payload.get("sender_pub")
                        content_sig_b64u = payload.get("content_sig")

                        if not ciphertext_b64u or not sender_uid or not sender_pub_b64u or not content_sig_b64u:
                            print("[recv] Malformed USER_DELIVER payload")
                            continue

                        try:
                            ciphertext = b64url_decode(ciphertext_b64u)
                            plaintext = rsa_oaep_decrypt(priv_pem, ciphertext).decode()

                            # Verify end-to-end signature
                            sender_pub_pem = der_b64url_to_public_pem(sender_pub_b64u)
                            sig_ok = rsa_pss_verify(sender_pub_pem, ciphertext, b64url_decode(content_sig_b64u))

                            if not sig_ok:
                                print(f"[SECURITY] Invalid content signature from {sender_uid}")
                                continue

                            # Remember the sender’s key if not already stored
                            if sender_uid not in known_pubkeys:
                                known_pubkeys[sender_uid] = sender_pub_pem

                            print(f"{display(sender_uid)}: {plaintext}")

                        except Exception as e:
                            print(f"[recv] Failed to process USER_DELIVER: {e}")

            except asyncio.CancelledError:
                pass

        # Run sender and receiver concurrently
        try:
            await asyncio.gather(sender(), receiver())
        except asyncio.CancelledError:
            print("Client tasks cancelled, shutting down...")

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOCP Secure Chat Client")
    parser.add_argument("--user", required=True, help="Human nickname (local only)")
    parser.add_argument("--server", required=True, help="Server WebSocket URL (e.g., ws://127.0.0.1:8765)")
    args = parser.parse_args()

    try:
        asyncio.run(run_client(args.user, args.server))
    except KeyboardInterrupt:
        print("\nDisconnected. Goodbye!")