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

Author: GROUP 12
MEMBERS:  
  1. Debasish Saha Pranta (a1963099, debasishsaha.pranta@student.adelaide.edu.au)
  2. Samin Yeasar Seaum (a1976022, saminyeasar.seaum@student.adelaide.edu.au)
  3. Abidul Kabir (a1974976, abidul.kabir@student.adelaide.edu.au)
  4. Sahar Alzahrani (a1938372, sahar.alzahrani@student.adelaide.edu.au)
  5. Mahrin Mahia (a1957342, mahrin.mahia@student.adelaide.edu.au)
  6. Maria Hasan Logno (a1975478, mariahasan.logno@student.adelaide.edu.au)

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
from cryptography.hazmat.primitives import serialization, hashes

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


CHUNK_SIZE = 256 * 1024  # 256 KB before encryption (adjust)
FILE_PING_EVERY = 50  # send a websocket ping every N file chunks

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


def canonical(obj: dict) -> bytes:
    # Deterministic JSON for signature input
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def make_content_sig(priv_pem: bytes, ciphertext_b64u: str, frm: str, to: str, ts: int) -> str:
    msg = {"ciphertext": ciphertext_b64u, "from": frm, "to": to, "ts": ts}
    sig = rsa_pss_sign(priv_pem, canonical(msg))
    return b64url_encode(sig)

def verify_content_sig(pub_pem: bytes, ciphertext_b64u: str, frm: str, to: str, ts: int, sig_b64u: str) -> bool:
    msg = {"ciphertext": ciphertext_b64u, "from": frm, "to": to, "ts": ts}
    return rsa_pss_verify(pub_pem, canonical(msg), b64url_decode(sig_b64u))
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
    async with websockets.connect(server_url, ping_interval=60, ping_timeout=360) as ws:
        # --- 1. Registration handshake -------------------------------------
        await ws.send(json.dumps({
            "type": "USER_HELLO",
            "from": proto_id,  # MUST be UUID v4
            "to": "*",
            "id": uuid.uuid4().hex,
            "ts": now_ms(),
            "payload": {
                "client": "cli-v1",
                "pubkey_b64u": public_pem_to_der_b64url(pub_pem),
                "enc_pubkey":  public_pem_to_der_b64url(pub_pem),
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

                    # Resolve target
                   # Resolve target (UUID or case-insensitive name) and require known key
                    dst = resolve_user_id(target_raw)
                    if not dst:
                        print(f"Unknown recipient '{target_raw}'. Try /list.")
                        continue
                    if dst not in known_pubkeys:
                        print(f"No public key for {display(dst)} yet. Wait for adverts or run /list.")
                        continue

                    # Encrypt and sign
                    ts = now_ms()
                    ct_bytes = rsa_oaep_encrypt(known_pubkeys[dst], msg_text.encode())
                    ct_b64u  = b64url_encode(ct_bytes)

                    payload = {
                        "ciphertext": ct_b64u,
                        "sender_pub": public_pem_to_der_b64url(pub_pem),
                        "content_sig": make_content_sig(priv_pem, ct_b64u, proto_id, dst, ts),
                    }
                    # Server verifies usig over json.dumps(payload, sort_keys=True) (with spaces),
                    # so we must sign the exact same bytes.
                    usig_bytes = rsa_pss_sign(priv_pem, json.dumps(payload, sort_keys=True).encode())
                    usig = b64url_encode(usig_bytes)

                    frame = {
                        "type": "MSG_DIRECT",
                        "from": proto_id,
                        "to": dst,
                        "id": uuid.uuid4().hex,
                        "ts": ts,
                        "payload": payload,
                        "usig": usig,
                    }
                    await ws.send(json.dumps(frame))


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
                    targets = [
                        uid for uid in known_pubkeys.keys()
                        if uid != proto_id
                        and UUID_RE.match(uid)  # only proper UUID v4 user ids
                        and not id_to_name.get(uid, "").startswith("server-")  # skip server IDs we learned
                    ]
                    if not targets:
                        print("[all] No known recipients yet; wait for advertisements or /list.")
                        continue

                    for target in targets:
                        try:
                            ts = now_ms()
                            ct_bytes = rsa_oaep_encrypt(known_pubkeys[target], msg_text.encode())
                            ct_b64u  = b64url_encode(ct_bytes)

                            payload = {
                                "ciphertext": ct_b64u,
                                "sender_pub": public_pem_to_der_b64url(pub_pem),
                                "content_sig": make_content_sig(priv_pem, ct_b64u, proto_id, target, ts),
                            }
                            # Server verifies usig over json.dumps(payload, sort_keys=True) (with spaces),
                            # so we must sign the exact same bytes.
                            usig_bytes = rsa_pss_sign(priv_pem, json.dumps(payload, sort_keys=True).encode())
                            usig = b64url_encode(usig_bytes)

                            frame = {
                                "type": "MSG_DIRECT",
                                "from": proto_id,
                                "to": target,
                                "id": uuid.uuid4().hex,
                                "ts": ts,
                                "payload": payload,
                                "usig": usig,
                            }
                            await ws.send(json.dumps(frame))
                        except Exception as e:
                            print(f"[all] Failed to send to {display(target)}: {e}")


                elif line.startswith("/sendfile "):
                    try:
                        _, to_str, path = line.split(maxsplit=2)
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

                    # read file & compute digest
                    with open(path, "rb") as f:
                        data = f.read()
                    sha256_hex = __import__("hashlib").sha256(data).hexdigest()

                    file_id = str(uuid.uuid4())
                    size = len(data)
                    name = os.path.basename(path)

                    # start
                    start = {
                        "type": "FILE_START",
                        "from": proto_id,
                        "to": dst,
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "payload": {
                            "file_id": file_id,
                            "name": name,
                            "size": size,
                            "sha256": sha256_hex,
                            "mode": "dm",
                        },
                    }
                    await ws.send(json.dumps(start))

                    # chunk & encrypt (RSA-OAEP per chunk under recipient pubkey)
                    sent = 0
                    idx = 0

                    # Compute the OAEP-safe max plaintext length for this recipient key
                    
                    def _oaep_max_len(pub_pem: bytes) -> int:
                        pub = serialization.load_pem_public_key(pub_pem)
                        key_bytes = (pub.key_size + 7) // 8                # e.g., 4096 bits -> 512 bytes
                        hlen = hashes.SHA256().digest_size                 # 32 bytes
                        return key_bytes - 2*hlen - 2                      # OAEP limit

                    recip_pub = known_pubkeys.get(dst)
                    if not recip_pub:
                        print(f"No public key for {display(dst)}; aborting file send.")
                        continue

                    max_len = _oaep_max_len(recip_pub)
                    if max_len <= 0:
                        print("Unsupported key/params for OAEP.")
                        continue

                    # Use the exact OAEP limit (optionally minus a few bytes for paranoia)
                    chunk_size = max_len  # e.g., 446 bytes for RSA-4096 + SHA-256
                    if not recip_pub:
                        print(f"No public key for {display(dst)}; aborting file send.")
                        continue

                    for off in range(0, size, chunk_size):
                        chunk = data[off:off+chunk_size]
                        loop = asyncio.get_running_loop()
                        ct_bytes = await loop.run_in_executor(None, rsa_oaep_encrypt, recip_pub, chunk)
                        ct_b64u  = b64url_encode(ct_bytes)

                        frame = {
                            "type": "FILE_CHUNK",
                            "from": proto_id,
                            "to": dst,
                            "id": uuid.uuid4().hex,
                            "ts": now_ms(),
                            "payload": {
                                "file_id": file_id,
                                "index": idx,
                                "ciphertext": ct_b64u,
                            },
                        }
                        await ws.send(json.dumps(frame))
                        idx += 1
                        sent += len(chunk)

                        # light pacing + keepalive so the server can reply/pong while we stream
                        if idx % FILE_PING_EVERY == 0:
                            try:
                                await ws.ping()
                            except Exception:
                                pass

                        if idx % 32 == 0 or sent == size:
                            print(f"  sent {sent}/{size} bytes...", end="\r")

                        await asyncio.sleep(0)  # yield to event loop

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
                        origin = payload.get("via")
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

                        # ✅ Improved display logic that uses payload['via'] if present
                        if origin and relay and origin == relay:
                            # user is hosted on this same server
                            print(f"🟢 [local] {display(uid)} is now online")
                        elif origin:
                            # remote user; show their real hosting server
                            print(f"🟢 [remote] {display(uid)} has joined the network via server {origin[:8]}")
                        else:
                            # backward compatibility for servers without 'via' field
                            if relay and relay != uid:
                                print(f"🟢 [remote] {display(uid)} has joined the network via server {relay[:8]}")
                            else:
                                print(f"🟢 [local] {display(uid)} is now online")


                    # ---------- Receive a direct encrypted message -----------
                    elif mtype == "MSG_DIRECT":
                        if not verify_transport_sig(msg, known_pubkeys):
                            print("[SECURITY] Invalid server transport signature.")
                            continue

                        p = msg.get("payload", {}) or {}
                        ct_b64u  = p.get("ciphertext")
                        sig_b64u = p.get("content_sig")
                        sender_pub_b64u = p.get("sender_pub")
                        sender_uid = msg.get("from")
                        recip_uid  = msg.get("to")
                        ts_msg     = msg.get("ts")

                        if not ct_b64u or not sig_b64u or not sender_pub_b64u or not sender_uid or not recip_uid or ts_msg is None:
                            print("[recv] Invalid MSG_DIRECT frame")
                            continue

                        try:
                            sender_pub_pem = der_b64url_to_public_pem(sender_pub_b64u)
                            # verify content_sig over (ciphertext|from|to|ts)
                            if not verify_content_sig(sender_pub_pem, ct_b64u, sender_uid, recip_uid, ts_msg, sig_b64u):
                                print(f"[SECURITY] BAD content_sig from {display(sender_uid)}")
                                continue

                            # cache sender key
                            if sender_uid not in known_pubkeys:
                                known_pubkeys[sender_uid] = sender_pub_pem

                            # decrypt
                            plaintext = rsa_oaep_decrypt(priv_pem, b64url_decode(ct_b64u)).decode()
                            print(f"{display(sender_uid)}: {plaintext}")
                        except Exception as e:
                            print(f"[recv] Failed to process MSG_DIRECT: {e}")

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
                        
                        p = msg.get("payload", {}) or {}
                        ct_b64u  = p.get("ciphertext")
                        sig_b64u = p.get("content_sig")
                        sender_uid = p.get("sender")
                        sender_pub_b64u = p.get("sender_pub")
                        recip_uid = proto_id
                        ts_msg = msg.get("ts")

                        if not ct_b64u or not sig_b64u or not sender_uid or not sender_pub_b64u or ts_msg is None:
                            print("[recv] Malformed USER_DELIVER payload")
                            continue

                        try:
                            sender_pub_pem = der_b64url_to_public_pem(sender_pub_b64u)

                            if not verify_content_sig(sender_pub_pem, ct_b64u, sender_uid, recip_uid, ts_msg, sig_b64u):
                                print(f"[SECURITY] Invalid content signature from {display(sender_uid)}")
                                continue

                            if sender_uid not in known_pubkeys:
                                known_pubkeys[sender_uid] = sender_pub_pem

                            plaintext = rsa_oaep_decrypt(priv_pem, b64url_decode(ct_b64u)).decode()
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
                        sha256_hex = p.get("sha256")

                        incoming_files[fid] = {
                            "name": name,
                            "size": size,
                            "bufs": {},
                            "sender": sender,
                            "received_bytes": 0,
                            "received_chunks": 0,
                            "sha256": sha256_hex,
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

                        if fid not in incoming_files:
                            incoming_files[fid] = {
                                "name": f"{fid}.bin",
                                "size": -1,
                                "bufs": {},
                                "sender": sender,
                                "received_bytes": 0,
                                "received_chunks": 0,
                                "sha256": None,
                            }

                        # decrypt the chunk
                        try:
                            loop = asyncio.get_running_loop()
                            ct_bytes = b64url_decode(ct)
                            pt = await loop.run_in_executor(None, rsa_oaep_decrypt, priv_pem, ct_bytes)
                        except Exception:
                            pt = b""

                        meta = incoming_files[fid]
                        meta["bufs"][int(idx)] = pt
                        meta["received_chunks"] += 1
                        meta["received_bytes"]  += len(pt)

                        expected = meta.get("size", -1)
                        print(f"[recv] chunk {idx} for {meta['name']} ({len(pt)} bytes)  "
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

                        # assemble
                        indices = sorted(meta["bufs"].keys())
                        data = b"".join(meta["bufs"][i] for i in indices)

                        # size check
                        expected = meta.get("size", -1)
                        if expected > 0 and len(data) != expected:
                            print(f"[warn] file size mismatch for {meta['name']}: got {len(data)} vs expected {expected}")
                            # (still proceed; spec doesn’t mandate drop on mismatch)

                        # sha256 check (if provided)
                        if meta.get("sha256"):
                            got = __import__("hashlib").sha256(data).hexdigest()
                            if got != meta["sha256"]:
                                print(f"[recv] sha256 mismatch for {meta['name']} — discarding")
                                continue

                        # save to downloads/
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
                    elif mtype == "ERROR":
                        p = msg.get("payload", {}) or {}
                        code = p.get("code")
                        detail = p.get("detail")
                        print(f"[server ERROR] {code}" + (f": {detail}" if detail else ""))
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