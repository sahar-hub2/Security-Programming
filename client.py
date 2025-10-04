"""
client.py
----------
SOCP client for secure chat communication.

Implements:
- RSA-based end-to-end encryption (OAEP-SHA256)
- RSASSA-PSS message signatures
- Base64url encoding (no padding)
- Commands: /tell, /all, /list
- Handles USER_ADVERTISE, USER_REMOVE, MSG_DIRECT, MSG_BROADCAST

Author: Your Group Name
"""

import asyncio, websockets, json, argparse, time, uuid
from keys import (
    load_or_create_keys,
    rsa_oaep_encrypt,
    rsa_oaep_decrypt,
    rsa_pss_sign,
    rsa_pss_verify,
    b64url_encode,
    b64url_decode,
)

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
        return False
    payload_bytes = json.dumps(msg.get("payload", {}), sort_keys=True).encode()
    try:
        return rsa_pss_verify(known_pubkeys[signer_id], payload_bytes, b64url_decode(sig_b64u))
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Main async client function
# ---------------------------------------------------------------------------

async def run_client(user_id: str, server_url: str):
    """
    Launch a single client instance that connects to a SOCP server,
    performs registration, and handles bidirectional message flow.
    """
    # Load (or create) a persistent RSA-4096 keypair for this user
    priv_pem, pub_pem = load_or_create_keys(user_id)

    # Store known public keys advertised by server (user_id -> PEM bytes)
    known_pubkeys: dict[str, bytes] = {}

    # Establish WebSocket connection to the target SOCP server
    async with websockets.connect(server_url, ping_interval=15, ping_timeout=45) as ws:
        # --- 1. Registration handshake -------------------------------------
        await ws.send(json.dumps({
            "type": "USER_HELLO",
            "from": user_id,
            "to": "*",
            "id": uuid.uuid4().hex,
            "ts": now_ms(),
            "payload": {"pubkey": pub_pem.decode()},
        }))
        print(f"Connected to {server_url} as {user_id}")

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
                        print("Usage: /tell <user> <message>")
                        continue
                    target, msg_text = parts[1], parts[2]

                    if target not in known_pubkeys:
                        print(f"No public key for {target}, cannot send encrypted message.")
                        continue

                    # Encrypt with recipient’s public key; sign ciphertext
                    ciphertext = rsa_oaep_encrypt(known_pubkeys[target], msg_text.encode())
                    signature  = rsa_pss_sign(priv_pem, ciphertext)

                    await ws.send(json.dumps({
                        "type": "MSG_DIRECT",
                        "from": user_id,
                        "to": target,
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "payload": {
                            "ciphertext": b64url_encode(ciphertext),
                            "signature":  b64url_encode(signature),
                        }
                    }))

                # -------------------- List Connected Users (/list) ------------
                elif line.strip() == "/list":
                    await ws.send(json.dumps({
                        "type": "CMD_LIST",
                        "from": user_id,
                        "to": "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms()
                    }))

                # -------------------- Broadcast Message (/all) ----------------
                elif line.startswith("/all "):
                    msg_text = line[len("/all "):]
                    await ws.send(json.dumps({
                        "type": "MSG_BROADCAST",
                        "from": user_id,
                        "to": "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "payload": {"text": msg_text}
                    }))

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
                        payload = msg.get("payload", {})
                        uid = payload.get("user")
                        pubkey = payload.get("pubkey")
                        relay = msg.get("relay") or msg.get("from")
                        if not uid or not pubkey:
                            continue

                        # Bootstrap TOFU: accept server's own key once
                        if relay not in known_pubkeys:
                            if uid == relay:
                                known_pubkeys[uid] = pubkey.encode()
                                print(f"[bootstrap] learned SERVER pubkey for {uid}")
                                # Process any buffered adverts now
                                for pend in list(pending_advertises):
                                    if verify_transport_sig(pend, known_pubkeys):
                                        p = pend["payload"]
                                        known_pubkeys[p["user"]] = p["pubkey"].encode()
                                        print(f"[server] learned pubkey for {p['user']}")
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
                        known_pubkeys[uid] = pubkey.encode()
                        print(f"[server] learned pubkey for {uid}")

                    # ---------- Receive a direct encrypted message -----------
                    elif mtype == "MSG_DIRECT":
                        if not verify_transport_sig(msg, known_pubkeys):
                            print("[SECURITY] Invalid server transport signature.")
                            continue
                        payload = msg.get("payload", {})
                        ciphertext_b64u = payload.get("ciphertext")
                        signature_b64u  = payload.get("signature")
                        sender_uid = msg.get("from")

                        if not ciphertext_b64u or not signature_b64u:
                            print(f"[recv] Invalid message from {sender_uid}")
                            continue
                        if sender_uid not in known_pubkeys:
                            print(f"Message from {sender_uid}, but no pubkey known.")
                            continue

                        ciphertext = b64url_decode(ciphertext_b64u)
                        signature  = b64url_decode(signature_b64u)

                        if not rsa_pss_verify(known_pubkeys[sender_uid], ciphertext, signature):
                            print(f"[SECURITY] Invalid signature from {sender_uid}!")
                            continue

                        plaintext = rsa_oaep_decrypt(priv_pem, ciphertext).decode()
                        print(f"{sender_uid}: {plaintext}")

                    # ---------- Handle USER_REMOVE (disconnection) ------------
                    elif mtype == "USER_REMOVE":
                        if not verify_transport_sig(msg, known_pubkeys):
                            print("[SECURITY] Invalid server transport signature.")
                            continue
                        payload = msg.get("payload", {})
                        removed_user = payload.get("user")
                        if removed_user:
                            known_pubkeys.pop(removed_user, None)
                            print(f"[server] User {removed_user} has disconnected.")

                    # ---------- Handle broadcast messages --------------------
                    elif mtype == "MSG_BROADCAST":
                        if not verify_transport_sig(msg, known_pubkeys):
                            print("[SECURITY] Invalid server transport signature.")
                            continue
                        payload = msg.get("payload", {})
                        text = payload.get("text")
                        sender_uid = msg.get("from")
                        if text:
                            print(f"[all] {sender_uid}: {text}")

                    # ---------- Handle user list result -----------------------
                    elif mtype == "CMD_LIST_RESULT":
                        if not verify_transport_sig(msg, known_pubkeys):
                            print("[SECURITY] Invalid server transport signature.")
                            continue
                        payload = msg.get("payload", {})
                        users = payload.get("users", [])
                        print(f"Connected users: {', '.join(users)}")

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
    parser.add_argument("--user", required=True, help="Unique user ID or nickname")
    parser.add_argument("--server", required=True, help="Server WebSocket URL (e.g., ws://127.0.0.1:8765)")
    args = parser.parse_args()

    try:
        asyncio.run(run_client(args.user, args.server))
    except KeyboardInterrupt:
        print("\nDisconnected. Goodbye!")