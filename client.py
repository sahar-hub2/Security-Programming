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

import asyncio, websockets, json, argparse, time, uuid, re, os, uuid, math, base64
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


CHUNK_SIZE = 256 * 1024  # 256 KB before encryption (adjust)

DOWNLOADS_DIR = os.path.join(os.getcwd(), "downloads")
os.makedirs(DOWNLOADS_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

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
        # File reassembly state (fid -> info)
    incoming_files: dict[str, dict] = {}

    def resolve_user_id(s: str) -> str | None:
        """Accept UUID directly; otherwise resolve by case-insensitive name."""
        if UUID_RE.match(s):
            return s
        return name_index.get(s.lower())

    def resolve_name(uid: str) -> str:
        return id_to_name.get(uid, uid)

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

                elif line.startswith("/sendfile "):
                    try:
                        _, to_str, path = line.split(maxsplit=2)   # <-- use line, not text
                    except ValueError:
                        print("usage: /sendfile <user|uuid> <path>")
                        continue

                    dst = resolve_user_id(to_str)
                    if not dst:
                        print(f"unknown recipient: {to_str}")
                        continue

                    if not os.path.isfile(path):
                        print(f"file not found: {path}")
                        continue

                    file_id = str(uuid.uuid4())
                    size = os.path.getsize(path)
                    name = os.path.basename(path)

                    # 1) FILE_START
                    start = {
                        "type": "FILE_START",
                        "from": proto_id,           # <-- your user id
                        "to": dst,
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "payload": {
                            "file_id": file_id,
                            "name": name,
                            "size": size,
                            "sha256": "",           # fill later if you want
                            "mode": "dm"
                        },
                    }
                    await ws.send(json.dumps(start))

                    # 2) FILE_CHUNK (demo "encryption" = base64 of raw bytes)
                    sent = 0
                    idx = 0
                    with open(path, "rb") as f:
                        while True:
                            chunk = f.read(CHUNK_SIZE)
                            if not chunk:
                                break

                            ciphertext = b64url_encode(chunk)  # replace with RSA-OAEP later

                            frame = {
                                "type": "FILE_CHUNK",
                                "from": proto_id,
                                "to": dst,
                                "id": uuid.uuid4().hex,
                                "ts": now_ms(),
                                "payload": {
                                    "file_id": file_id,
                                    "index": idx,
                                    "ciphertext": ciphertext
                                },
                            }
                            await ws.send(json.dumps(frame))
                            idx += 1
                            sent += len(chunk)
                            if idx % 32 == 0 or sent == size:
                                print(f"  sent {sent}/{size} bytes...", end="\r")
                            await asyncio.sleep(0)  # yield

                    # 3) FILE_END
                    end = {
                        "type": "FILE_END",
                        "from": proto_id,
                        "to": dst,
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "payload": {"file_id": file_id},
                    }
                    await ws.send(json.dumps(end))
                    print(f"\nFile sent: {name} ({size} bytes) in {idx} chunks")
                    continue
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
                    # TEMP DEBUG (you can comment out later)
                    if mtype and mtype.startswith("USER_FILE_"):
                        print(f"[debug] rx {mtype}")

                    # ---------- Receive a USER_ADVERTISE ---------------------
                    if mtype == "USER_ADVERTISE":
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

                    elif mtype == "USER_FILE_START":
                        if not verify_transport_sig(msg, known_pubkeys):
                            print("[SECURITY] Invalid server transport signature on USER_FILE_START.")
                            continue
                        p = msg.get("payload", {}) or {}
                        fid = p.get("file_id")
                        name = p.get("name") or f"{fid}.bin"
                        size = int(p.get("size") or -1)
                        sender = p.get("sender")
                        incoming_files[fid] = {
                            "name": name,
                            "size": size,
                            "bufs": {},
                            "sender": sender,
                            "received_bytes": 0,     # <-- init
                            "received_chunks": 0,    # <-- init
                        }
                        print(f"\n[recv] File incoming from {resolve_name(sender)}: {name} ({size} bytes)")
                        continue
                    
                    elif mtype == "USER_FILE_CHUNK":
                        if not verify_transport_sig(msg, known_pubkeys):
                            print("[SECURITY] Invalid server transport signature on USER_FILE_CHUNK.")
                            continue

                        p   = msg.get("payload", {}) or {}
                        fid = p.get("file_id")
                        idx = p.get("index")
                        ct  = p.get("ciphertext")
                        sender = p.get("sender")

                        if fid is None or idx is None or ct is None:
                            print("[recv] Malformed USER_FILE_CHUNK payload:", p)
                            continue

                        # Ensure we have a record (in case CHUNK arrives before START)
                        if fid not in incoming_files:
                            incoming_files[fid] = {
                                "name": f"{fid}.bin",
                                "size": -1,
                                "bufs": {},
                                "sender": sender,
                                "received_bytes": 0,
                                "received_chunks": 0,
                            }

                        # Decode and store
                        try:
                            plaintext = b64url_decode(ct)
                        except Exception:
                            plaintext = b""

                        incoming_files[fid]["bufs"][idx] = plaintext
                        incoming_files[fid]["received_chunks"] += 1
                        incoming_files[fid]["received_bytes"]  += len(plaintext)

                        meta = incoming_files[fid]
                        expected = meta.get("size", -1)
                        print(f"[recv] chunk {idx} for {meta['name']} ({len(plaintext)} bytes)  "
                            f"total={meta['received_chunks']} chunks, "
                            f"{meta['received_bytes']}/{expected if expected>0 else '?'} bytes")

                    elif mtype == "USER_FILE_END":
                        if not verify_transport_sig(msg, known_pubkeys):
                            print("[SECURITY] Invalid server transport signature on USER_FILE_END.")
                            continue

                        p   = msg.get("payload", {}) or {}
                        fid = p.get("file_id")

                        meta = incoming_files.pop(fid, None)
                        if not meta:
                            print("[recv] FILE_END for unknown file:", fid)
                            continue

                        # --- sanity / visibility before reassembly ---
                        recv_chunks = len(meta.get("bufs", {}))
                        recv_bytes  = sum(len(meta["bufs"][i]) for i in meta["bufs"])
                        expected    = meta.get("size", -1)

                        # detect gaps (missing indices)
                        indices = sorted(meta["bufs"].keys())
                        missing = []
                        if indices:
                            # expected contiguous 0..max_idx
                            max_idx = indices[-1]
                            missing = [i for i in range(max_idx + 1) if i not in meta["bufs"]]

                        if missing:
                            print(f"[warn] Missing {len(missing)} chunk(s) for {meta['name']}: first few -> {missing[:10]}")

                        print(f"[debug] END for {meta['name']}: {recv_chunks} chunks, {recv_bytes}"
                            + (f"/{expected} bytes" if expected > 0 else "/? bytes"))

                        # --- reassemble in order 0..N-1 (whatever we have) ---
                        data = b"".join(meta["bufs"][i] for i in indices)

                        # size sanity
                        if expected > 0 and len(data) != expected:
                            print(f"[warn] file size mismatch for {meta['name']}: got {len(data)} vs expected {expected}")

                        # --- save to downloads/ (avoid overwrite) ---
                        safe_name = meta["name"]
                        outpath = os.path.join(DOWNLOADS_DIR, safe_name)
                        base, ext = os.path.splitext(outpath)
                        k = 1
                        while os.path.exists(outpath):
                            outpath = f"{base}({k}){ext}"
                            k += 1

                        try:
                            with open(outpath, "wb") as w:
                                w.write(data)
                            print(f"[recv] File saved: {outpath} ({len(data)} bytes) from {resolve_name(meta['sender'])}")
                        except Exception as e:
                            print(f"[error] failed to save {safe_name}: {e}")

                        continue
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