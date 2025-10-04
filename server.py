"""
server.py
----------
SOCP-compatible server for secure chat.

Responsibilities:
- Manage WebSocket connections for local users
- Advertise user public keys to all clients (DER+base64url on the wire)
- Deliver encrypted direct messages
- Broadcast public messages (local only; kept for system notices)
- Handle user join/leave notifications
- Sign all outbound payloads (transport-level integrity) with RSASSA-PSS
- Include human-friendly names in adverts and /list for better UX
- §7 JSON Envelope: verify 'usig' on user content (MSG_DIRECT)

Author: Your Group Name
"""

import asyncio, json, argparse, time, websockets, uuid
from websockets import serve
from collections import deque

from keys import (
    b64url_encode,
    rsa_pss_sign,
    rsa_pss_verify,
    b64url_decode,
    generate_rsa4096,
    public_pem_to_der_b64url,
    der_b64url_to_public_pem,
    load_or_create_server_uuid,
    is_uuid_v4,
)

# Static bootstrap list of introducers (normally YAML/config file)
bootstrap_servers = [
    {"host": "127.0.0.1", "port": 9001,
     "pubkey": "BASE64URL_OF_INTRODUCER_PUBKEY"},
    # {"host": "127.0.0.1", "port": 9002,
    #  "pubkey": "BASE64URL_OF_INTRODUCER_PUBKEY"},
]

# ---------------------------------------------------------------------------
# Freshness / dedup helpers
# ---------------------------------------------------------------------------
RECENT_IDS = deque(maxlen=4096)

def now_ms() -> int:
    return int(time.time() * 1000)

def fresh_ts(ts_ms: int, skew_ms: int = 120_000) -> bool:
    now = now_ms()
    try:
        return abs(now - int(ts_ms)) <= skew_ms
    except Exception:
        return False

def seen_before(mid: str) -> bool:
    if not isinstance(mid, str):
        return True
    if mid in RECENT_IDS:
        return True
    RECENT_IDS.append(mid)
    return False

# ---------------------------------------------------------------------------
# In-memory tables (runtime-only; no persistent state)
# ---------------------------------------------------------------------------
servers = {}          # server_id -> websocket (reserved for federation)
server_addrs = {}     # server_id -> (host, port, pubkey_pem)
local_users = {}      # user_uuid -> websocket (connected locally)
user_locations = {}   # user_uuid -> "local" or server_id (federated)
user_pubkeys = {}     # user_uuid -> public key PEM string
user_names = {}       # user_uuid -> human-friendly name (optional)

# ---------------------------------------------------------------------------
# Server identity (ephemeral RSA-4096 for transport signing)
# ---------------------------------------------------------------------------
priv_pem, pub_pem = generate_rsa4096()
server_pubkeys = {}   # map of other servers’ pubkeys (future federation use)

# ---------------------------------------------------------------------------
# Helper: sign any JSON payload deterministically
# ---------------------------------------------------------------------------
def sign_payload(payload: dict) -> str:
    """
    Compute RSASSA-PSS signature over canonical JSON representation
    (keys sorted). Returns base64url string with no padding.
    """
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    return b64url_encode(rsa_pss_sign(priv_pem, payload_bytes))

def build_server_hello_join(my_id, host, port, pubkey_b64u):
    return {
        "type": "SERVER_HELLO_JOIN",
        "from": my_id,
        "id": my_id,
        "to": f"{host}:{port}",
        "ts": now_ms(),
        "payload": {
            "host": host,
            "port": port,
            "pubkey": pubkey_b64u
        },
        "sig": sign_payload({"host": host, "port": port, "pubkey": pubkey_b64u})
    }

def build_server_announce(my_id, host, port, pubkey_b64u):
    return {
        "type": "SERVER_ANNOUNCE",
        "from": my_id,
        "id": my_id,
        "to": "*",
        "ts": now_ms(),
        "payload": {
            "host": host,
            "port": port,
            "pubkey": pubkey_b64u
        },
        "sig": sign_payload({"host": host, "port": port, "pubkey": pubkey_b64u})
    }

# ---------------------------------------------------------------------------
# Main per-connection handler
# ---------------------------------------------------------------------------
async def bootstrap_with_introducer(my_id, host, port, pubkey_b64u):
    for entry in bootstrap_servers:
        introducer_uri = f"ws://{entry['host']}:{entry['port']}"
        try:
            async with websockets.connect(introducer_uri) as ws:
                join_msg = build_server_hello_join(my_id, host, port, pubkey_b64u)
                await ws.send(json.dumps(join_msg))

                raw = await ws.recv()
                msg = json.loads(raw)
                if msg.get("type") == "SERVER_WELCOME":
                    assigned_id = msg["payload"]["assigned_id"]
                    servers.update({
                        s["server_id"]: None for s in msg["payload"].get("servers", [])
                    })
                    print(f"[bootstrap] Got assigned_id={assigned_id}, known servers={list(servers.keys())}")
                    return assigned_id
        except Exception as e:
            print(f"[bootstrap] Failed to connect to {introducer_uri}: {e}")
            raise RuntimeError("Could not connect to any introducer")


async def handle_ws(websocket, server_id: str, server_name: str):
    global pub_pem
    print(f"[{server_id}] New connection received.")
    """
    Handle a single WebSocket connection from a local user.
    Performs registration, message routing, and cleanup on disconnect.
    """
    user_id = None
    try:
        async for raw in websocket:
            # --- Parse incoming message JSON --------------------------------
            try:
                msg = json.loads(raw)
                print(f"websocket message: {msg}")
            except Exception as e:
                print(f"error message: {e}")
                # Invalid JSON; send ERROR response
                error_msg = {
                    "type": "ERROR",
                    "from": server_id,
                    "to": "*",
                    "id": uuid.uuid4().hex,
                    "ts": now_ms(),
                    "relay": server_id,
                    "payload": {"code": "BAD_JSON", "detail": str(e)},
                }
                error_msg["sig"] = sign_payload(error_msg["payload"])
                await websocket.send(json.dumps(error_msg))
                continue

            # --- freshness + dedup for all incoming client messages ----------
            mid = msg.get("id")
            ts = msg.get("ts")

            if mid is None or ts is None:
                err = {
                    "type": "ERROR",
                    "from": server_id,
                    "to": msg.get("from", "*"),
                    "id": uuid.uuid4().hex,
                    "ts": now_ms(),
                    "relay": server_id,
                    "payload": {"code": "MISSING_ID_OR_TS"},
                }
                err["sig"] = sign_payload(err["payload"])
                print(f"error #193")
                await websocket.send(json.dumps(err))
                continue

            if not fresh_ts(ts):
                err = {
                    "type": "ERROR",
                    "from": server_id,
                    "to": msg.get("from", "*"),
                    "id": uuid.uuid4().hex,
                    "ts": now_ms(),
                    "relay": server_id,
                    "payload": {"code": "STALE_TS"},
                }
                err["sig"] = sign_payload(err["payload"])
                await websocket.send(json.dumps(err))
                continue

            if seen_before(mid):
                # silently ignore duplicates
                continue

            mtype = msg.get("type")
            print(f"mtype: {mtype}")

            # ================================================================
            # 1. USER_HELLO — client registration (user_id MUST be UUID v4)
            # ================================================================
            if mtype == "USER_HELLO":
                user_id = msg.get("from")
                payload = msg.get("payload", {}) or {}
                pubkey_b64u = payload.get("pubkey_b64u")
                name = payload.get("name")  # optional nickname for UX

                # --- Validate registration fields ----------------------------
                if not user_id or not pubkey_b64u or not is_uuid_v4(user_id):
                    error_msg = {
                        "type": "ERROR",
                        "from": server_id,
                        "to": "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {"code": "MISSING_OR_INVALID_USER_ID_OR_PUBKEY"},
                    }
                    error_msg["sig"] = sign_payload(error_msg["payload"])
                    await websocket.send(json.dumps(error_msg))
                    continue

                # --- Enforce unique UUID -------------------------------------
                if user_id in local_users:
                    error_msg = {
                        "type": "ERROR",
                        "from": server_id,
                        "to": user_id,
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {"code": "NAME_IN_USE", "detail": user_id},
                    }
                    error_msg["sig"] = sign_payload(error_msg["payload"])
                    await websocket.send(json.dumps(error_msg))
                    continue

                # --- Convert wire key (DER+b64url) to PEM for internal use ---
                pubkey_pem = der_b64url_to_public_pem(pubkey_b64u)

                # --- Record local user ---------------------------------------
                local_users[user_id] = websocket
                user_locations[user_id] = "local"
                user_pubkeys[user_id] = pubkey_pem.decode()
                user_names[user_id] = name or user_id  # fallback to UUID if no name
                print(f"[{server_id}] User {user_names[user_id]} ({user_id}) connected locally.")

                # --- Send server’s own pubkey FIRST (bootstrap TOFU) ----------
                server_advertise = {
                    "type": "USER_ADVERTISE",
                    "from": server_id,
                    "to": user_id,
                    "id": uuid.uuid4().hex,
                    "ts": now_ms(),
                    "relay": server_id,  # who signed transport
                    "payload": {
                        "user": server_id,
                        "name": server_name,
                        "pubkey_b64u": public_pem_to_der_b64url(pub_pem),
                    },
                }
                server_advertise["sig"] = sign_payload(server_advertise["payload"])
                await websocket.send(json.dumps(server_advertise))
                
                print(f"[{server_id}] Sent USER_ADVERTISE (server pubkey) to {user_id}")
                print(f"[{server_id}] pubkey_b64u length = {len(public_pem_to_der_b64url(pub_pem))}")

                # --- THEN send all existing users’ pubkeys to the new user ---
                for uid, pk_pem_str in user_pubkeys.items():
                    if uid != user_id:
                        pk_pem_bytes = pk_pem_str.encode() if isinstance(pk_pem_str, str) else pk_pem_str
                        advertise_msg = {
                            "type": "USER_ADVERTISE",
                            "from": server_id,
                            "to": user_id,
                            "id": uuid.uuid4().hex,
                            "ts": now_ms(),
                            "relay": server_id,
                            "payload": {
                                "user": uid,
                                "name": user_names.get(uid, uid),
                                "pubkey_b64u": public_pem_to_der_b64url(pk_pem_bytes),
                            },
                        }
                        advertise_msg["sig"] = sign_payload(advertise_msg["payload"])
                        await websocket.send(json.dumps(advertise_msg))

                # --- Broadcast this user to all others ------------------------
                advertise_msg = {
                    "type": "USER_ADVERTISE",
                    "from": server_id,
                    "to": "*",
                    "id": uuid.uuid4().hex,
                    "ts": now_ms(),
                    "relay": server_id,
                    "payload": {
                        "user": user_id,
                        "name": user_names.get(user_id, user_id),
                        "pubkey_b64u": public_pem_to_der_b64url(pubkey_pem),
                    },
                }
                advertise_msg["sig"] = sign_payload(advertise_msg["payload"])
                for uid, ws in list(local_users.items()):
                    if ws != websocket:
                        try:
                            await ws.send(json.dumps(advertise_msg))
                        except Exception as e:
                            print(f"[{server_id}] Failed to advertise {user_id} to {uid}: {e}")
                # --- Gossip USER_ADVERTISE to all known servers ----------------
                gossip_payload = {
                    "user_id": user_id,
                    "server_id": server_id,
                    "meta": {"name": user_names.get(user_id, user_id)},
                }
                gossip_msg = {
                    "type": "USER_ADVERTISE",
                    "from": server_id,
                    "to": "*",
                    "ts": now_ms(),
                    "payload": gossip_payload,
                }
                gossip_msg["sig"] = sign_payload(gossip_payload)

                for sid, link in list(servers.items()):
                    if link and link.open:
                        try:
                            await link.send(json.dumps(gossip_msg))
                            print(f"[{server_id}] Gossiped USER_ADVERTISE for {user_id} to {sid}")
                        except Exception as e:
                            print(f"[{server_id}] Failed gossip to {sid}: {e}")
                continue
            # ================================================================
            # 2. MSG_DIRECT — encrypted private message (UUID v4 src/dst)
            #    §7: verify user envelope signature 'usig' over canonical payload
            # ================================================================
            elif mtype == "MSG_DIRECT":
                src = msg.get("from")
                dst = msg.get("to")
                payload = msg.get("payload", {}) or {}

                # --- Validate mandatory fields & UUID shape -------------------
                if not src or not dst or not is_uuid_v4(src) or not is_uuid_v4(dst):
                    error_msg = {
                        "type": "ERROR",
                        "from": server_id,
                        "to": src or "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {"code": "INVALID_SRC_OR_DST_UUID"},
                    }
                    error_msg["sig"] = sign_payload(error_msg["payload"])
                    print(f"error #372")
                    await websocket.send(json.dumps(error_msg))
                    continue

                # --- Verify user's envelope signature (usig) ------------------
                usig_b64u = msg.get("usig")
                if not usig_b64u:
                    error_msg = {
                        "type": "ERROR",
                        "from": server_id,
                        "to": src or "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {"code": "MISSING_USER_SIG"},
                    }
                    error_msg["sig"] = sign_payload(error_msg["payload"])
                    print(f"error #389")
                    await websocket.send(json.dumps(error_msg))
                    continue

                sender_pub_pem_str = user_pubkeys.get(src)
                if not sender_pub_pem_str:
                    error_msg = {
                        "type": "ERROR",
                        "from": server_id,
                        "to": src or "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {"code": "UNKNOWN_SENDER"},
                    }
                    error_msg["sig"] = sign_payload(error_msg["payload"])
                    await websocket.send(json.dumps(error_msg))
                    continue

                payload_bytes = json.dumps(payload, sort_keys=True).encode()
                if not rsa_pss_verify(sender_pub_pem_str.encode(), payload_bytes, b64url_decode(usig_b64u)):
                    error_msg = {
                        "type": "ERROR",
                        "from": server_id,
                        "to": src or "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {"code": "BAD_USER_SIG"},
                    }
                    error_msg["sig"] = sign_payload(error_msg["payload"])
                    await websocket.send(json.dumps(error_msg))
                    continue

                # --- Resolve destination -------------------------------------
                loc = user_locations.get(dst)
                if loc is None:
                    error_msg = {
                        "type": "ERROR",
                        "from": server_id,
                        "to": src,
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {"code": "USER_NOT_FOUND", "detail": dst},
                    }
                    error_msg["sig"] = sign_payload(error_msg["payload"])
                    await websocket.send(json.dumps(error_msg))
                    continue

                # --- Deliver to local recipient ------------------------------
                if loc == "local":
                    deliver = {
                        "type": "MSG_DIRECT",
                        "from": src,          # sender user id (UUID v4)
                        "to": dst,
                        "id": mid,            # keep original client id
                        "ts": now_ms(),
                        "relay": server_id,   # transport signer
                        "payload": payload,   # unchanged; receiver verifies inner signature
                        "usig": usig_b64u,    # (optional) forward user envelope sig for auditing
                    }
                    deliver["sig"] = sign_payload(deliver["payload"])
                    target_ws = local_users.get(dst)
                    if target_ws:
                        try:
                            await target_ws.send(json.dumps(deliver))
                            print(f"[{server_id}] Delivered {user_names.get(src, src)} -> {user_names.get(dst, dst)}")
                        except Exception as e:
                            print(f"[{server_id}] Delivery to {dst} failed: {e}")
                else:
                    # --- Forward to remote server via SERVER_DELIVER -------------
                    target_sid = loc  # which server hosts the recipient
                    deliver_payload = {
                        "user_id": dst,
                        "ciphertext": payload.get("ciphertext"),
                        "sender": src,
                        "sender_pub": payload.get("sender_pub"),
                        "content_sig": payload.get("content_sig"),
                    }
                    deliver_msg = {
                        "type": "SERVER_DELIVER",
                        "from": server_id,          # my server ID
                        "to": target_sid,           # recipient’s server
                        "ts": now_ms(),
                        "payload": deliver_payload,
                    }
                    deliver_msg["sig"] = sign_payload(deliver_payload)

                    target_ws = servers.get(target_sid)
                    if target_ws:
                        try:
                            await target_ws.send(json.dumps(deliver_msg))
                            print(f"[{server_id}] Forwarded MSG_DIRECT from {src} -> {dst} via {target_sid}")
                        except Exception as e:
                            print(f"[{server_id}] Failed SERVER_DELIVER to {target_sid}: {e}")
                    else:
                        print(f"[{server_id}] No connection to server {target_sid}, dropping message.")
                continue

            # ================================================================
            # 3. MSG_BROADCAST — public message to all users (system use)
            #    NOTE: Clients now implement E2EE fan-out for '/all'.
            # ================================================================
            elif mtype == "MSG_BROADCAST":
                src = msg.get("from")
                payload = msg.get("payload", {}) or {}
                if not src or "text" not in payload:
                    continue

                text = payload["text"]
                deliver_msg = {
                    "type": "MSG_BROADCAST",
                    "from": src,
                    "to": "*",
                    "id": mid,            # keep original client id
                    "ts": now_ms(),
                    "relay": server_id,   # transport signer
                    "payload": {"text": text},
                }
                deliver_msg["sig"] = sign_payload(deliver_msg["payload"])

                for uid, ws in list(local_users.items()):
                    if ws != websocket and uid != src:
                        try:
                            await ws.send(json.dumps(deliver_msg))
                        except Exception as e:
                            print(f"[{server_id}] Broadcast delivery to {uid} failed: {e}")
                print(f"[{server_id}] Broadcast from {user_names.get(src, src)}: {text}")

            # ================================================================
            # 4. CMD_LIST — respond with currently connected users
            # ================================================================
            elif mtype == "CMD_LIST":
                src = msg.get("from")
                if not src:
                    continue
                users_list = sorted(list(local_users.keys()))
                names_map = {uid: user_names.get(uid, uid) for uid in users_list}
                response = {
                    "type": "CMD_LIST_RESULT",
                    "from": server_id,
                    "to": src,
                    "id": uuid.uuid4().hex,
                    "ts": now_ms(),
                    "relay": server_id,
                    "payload": {
                        "users": users_list,
                        "names": names_map,   # map uuid -> display name
                    },
                }
                response["sig"] = sign_payload(response["payload"])
                try:
                    await websocket.send(json.dumps(response))
                except Exception as e:
                    print(f"[{server_id}] Failed to send CMD_LIST_RESULT to {src}: {e}")
                continue

            # ================================================================
            # 5. CTRL_CLOSE — application-level heartbeat (spec §8.4)
            # ================================================================
            elif mtype == "CTRL_CLOSE":
                src = msg.get("from")
                if not src:
                    continue
                ack = {
                    "type": "CTRL_CLOSE_ACK",
                    "from": server_id,
                    "to": src,
                    "id": uuid.uuid4().hex,
                    "ts": now_ms(),
                    "relay": server_id,
                    "payload": {
                        "echo_id": mid,          # client message id we’re acknowledging
                        "server_ts": now_ms(),   # server’s current time (ms)
                        "note": "app-heartbeat",
                    },
                }
                ack["sig"] = sign_payload(ack["payload"])
                try:
                    await websocket.send(json.dumps(ack))
                except Exception as e:
                    print(f"[{server_id}] Failed to send CTRL_CLOSE_ACK to {src}: {e}")
                continue
            # ================================================================
            # SERVER_HELLO_JOIN — introducer assigns server_id and replies
            # ================================================================
            elif mtype == "SERVER_HELLO_JOIN":
                print(f"IN SERVER_HELLO_JOIN")
                payload = msg.get("payload", {}) or {}
                host = payload.get("host")
                port = payload.get("port")
                pubkey_b64u = payload.get("pubkey")
                joining_id = msg.get("from")

                print(f"[{server_id}] Received SERVER_HELLO_JOIN from {joining_id}")

                # Validate required fields
                if not host or not port or not pubkey_b64u:
                    error_msg = {
                        "type": "ERROR",
                        "from": server_id,
                        "to": joining_id or "*",
                        "ts": now_ms(),
                        "payload": {"code": "MISSING_FIELDS"},
                    }
                    error_msg["sig"] = sign_payload(error_msg["payload"])
                    await websocket.send(json.dumps(error_msg))
                    return

                # Ensure unique server_id (reuse if available, else assign new UUID)
                assigned_id = joining_id
                if assigned_id in server_addrs:
                    assigned_id = str(uuid.uuid4())
                    print(f"[introducer] Duplicate requested ID, assigned new one: {assigned_id}")

                # Register the new server
                server_addrs[assigned_id] = (host, port, pubkey_b64u)
                servers[assigned_id] = websocket
                print(f"[introducer] Registered server {assigned_id} at {host}:{port}")

                # Prepare SERVER_WELCOME response
                welcome_payload = {
                    "assigned_id": assigned_id,
                    "servers": [
                        {"server_id": sid, "host": h, "port": p, "pubkey": pk}
                        for sid, (h, p, pk) in server_addrs.items()
                    ],
                }
                welcome_msg = {
                    "type": "SERVER_WELCOME",
                    "from": server_id,
                    "to": assigned_id,
                    "ts": now_ms(),
                    "payload": welcome_payload,
                }
                welcome_msg["sig"] = sign_payload(welcome_payload)
                await websocket.send(json.dumps(welcome_msg))
                return

            elif mtype == "SERVER_ANNOUNCE":
                payload = msg.get("payload", {}) or {}
                new_sid = msg.get("from")
                host = payload.get("host")
                port = payload.get("port")
                pubkey_b64u = payload.get("pubkey")

                # Validate
                if not new_sid or not host or not port or not pubkey_b64u:
                    print("[announce] Invalid SERVER_ANNOUNCE payload")
                    return

                # Verify signature
                sig_ok = rsa_pss_verify(pub_pem, json.dumps(payload, sort_keys=True).encode(), b64url_decode(msg.get("sig")))
                if not sig_ok:
                    print(f"[announce] BAD SIGNATURE from {new_sid}, ignoring")
                    return

                # Register the server
                server_addrs[new_sid] = (host, port, pubkey_b64u)
                print(f"[announce] Registered new server {new_sid} at {host}:{port}")
            elif mtype == "USER_ADVERTISE":
                payload = msg.get("payload", {})
                uid = payload.get("user_id")
                origin_sid = payload.get("server_id")

                # Verify signature using sender server pubkey
                sig_b64u = msg.get("sig")
                if not sig_b64u or origin_sid not in server_addrs:
                    return
                pubkey_b64u = server_addrs[origin_sid][2]
                pub_pem = der_b64url_to_public_pem(pubkey_b64u)
                if not rsa_pss_verify(pub_pem, json.dumps(payload, sort_keys=True).encode(), b64url_decode(sig_b64u)):
                    print(f"[gossip] BAD SIGNATURE in USER_ADVERTISE from {origin_sid}")
                    return

                # Update mapping
                user_locations[uid] = origin_sid
                print(f"[gossip] Learned user {uid} is on server {origin_sid}")

                # Forward to other servers (except the one we got it from)
                for sid, link in list(servers.items()):
                    if link == websocket:  # don’t send back
                        continue
                    try:
                        await link.send(json.dumps(msg))
                    except Exception as e:
                        print(f"[gossip] Failed to forward USER_ADVERTISE to {sid}: {e}")

            elif mtype == "USER_REMOVE":
                payload = msg.get("payload", {})
                uid = payload.get("user_id")
                origin_sid = payload.get("server_id")

                sig_b64u = msg.get("sig")
                if not sig_b64u or origin_sid not in server_addrs:
                    return
                pubkey_b64u = server_addrs[origin_sid][2]
                pub_pem = der_b64url_to_public_pem(pubkey_b64u)
                if not rsa_pss_verify(pub_pem, json.dumps(payload, sort_keys=True).encode(), b64url_decode(sig_b64u)):
                    print(f"[gossip] BAD SIGNATURE in USER_REMOVE from {origin_sid}")
                    return

                if user_locations.get(uid) == origin_sid:
                    user_locations.pop(uid, None)
                    print(f"[gossip] Removed user {uid} from server {origin_sid}")

                # Forward to others
                for sid, link in list(servers.items()):
                    if link == websocket:
                        continue
                    try:
                        await link.send(json.dumps(msg))
                    except Exception as e:
                        print(f"[gossip] Failed to forward USER_REMOVE to {sid}: {e}")
            elif mtype == "SERVER_DELIVER":
                payload = msg.get("payload", {}) or {}
                recipient = payload.get("user_id")
                sender = payload.get("sender")

                # Verify signature from the sending server
                sig_b64u = msg.get("sig")
                origin_sid = msg.get("from")
                if not sig_b64u or origin_sid not in server_addrs:
                    print(f"[{server_id}] SERVER_DELIVER missing sig or unknown origin")
                    return

                pubkey_b64u = server_addrs[origin_sid][2]
                pub_pem = der_b64url_to_public_pem(pubkey_b64u)
                if not rsa_pss_verify(pub_pem, json.dumps(payload, sort_keys=True).encode(), b64url_decode(sig_b64u)):
                    print(f"[{server_id}] BAD SIG on SERVER_DELIVER from {origin_sid}")
                    return

                # If recipient is local, deliver to them as USER_DELIVER
                if user_locations.get(recipient) == "local":
                    user_ws = local_users.get(recipient)
                    if user_ws:
                        deliver_payload = {
                            "ciphertext": payload.get("ciphertext"),
                            "sender": sender,
                            "sender_pub": payload.get("sender_pub"),
                            "content_sig": payload.get("content_sig"),
                        }
                        user_msg = {
                            "type": "USER_DELIVER",
                            "from": server_id,
                            "to": recipient,
                            "ts": now_ms(),
                            "payload": deliver_payload,
                        }
                        user_msg["sig"] = sign_payload(deliver_payload)
                        try:
                            await user_ws.send(json.dumps(user_msg))
                            print(f"[{server_id}] Delivered remote message {sender} -> {recipient}")
                        except Exception as e:
                            print(f"[{server_id}] Failed USER_DELIVER to {recipient}: {e}")
                else:
                    # Recipient not here — forward again if possible
                    target_sid = user_locations.get(recipient)
                    if target_sid and target_sid in servers and servers[target_sid].open:
                        try:
                            await servers[target_sid].send(json.dumps(msg))
                            print(f"[{server_id}] Forwarded SERVER_DELIVER for {recipient} to {target_sid}")
                        except Exception as e:
                            print(f"[{server_id}] Failed to forward SERVER_DELIVER to {target_sid}: {e}")
                    else:
                        print(f"[{server_id}] Unknown location for {recipient}, dropping SERVER_DELIVER.")

            # ================================================================
            # 6. Unknown or unsupported message type
            # ================================================================
            else:
                print(f"[{server_id}] Unknown msg type: {mtype}")

    # -----------------------------------------------------------------------
    # Connection closed or aborted
    # -----------------------------------------------------------------------
    except websockets.exceptions.ConnectionClosedOK:
        print(f"[{server_id}] WebSocket closed normally for {user_id}")
    except Exception as e:
        print(f"[{server_id}] recv_loop error: {e}")
    finally:
        # --- Cleanup user state after disconnect ----------------------------
        if user_id and websocket.close_code is not None:
            local_users.pop(user_id, None)
            user_locations.pop(user_id, None)
            user_pubkeys.pop(user_id, None)
            user_names.pop(user_id, None)
            print(f"[{server_id}] User {user_id} disconnected and cleaned up.")

            remove_msg = {
                "type": "USER_REMOVE",
                "from": server_id,
                "to": "*",
                "id": uuid.uuid4().hex,
                "ts": now_ms(),
                "relay": server_id,
                "payload": {"user": user_id},
            }
            remove_msg["sig"] = sign_payload(remove_msg["payload"])
            for uid, ws in list(local_users.items()):
                try:
                    await ws.send(json.dumps(remove_msg))
                except Exception as e:
                    print(f"[{server_id}] Failed to send USER_REMOVE to {uid}: {e}")
            # --- Gossip USER_REMOVE to all known servers -------------------
            gossip_payload = {"user_id": user_id, "server_id": server_id}
            gossip_msg = {
                "type": "USER_REMOVE",
                "from": server_id,
                "to": "*",
                "ts": now_ms(),
                "payload": gossip_payload,
            }
            gossip_msg["sig"] = sign_payload(gossip_payload)

            for sid, link in list(servers.items()):
                if link and link.open:
                    try:
                        await link.send(json.dumps(gossip_msg))
                        print(f"[{server_id}] Gossiped USER_REMOVE for {user_id} to {sid}")
                    except Exception as e:
                        print(f"[{server_id}] Gossip remove failed to {sid}: {e}")

# ---------------------------------------------------------------------------
# Main server loop
# ---------------------------------------------------------------------------
async def main_loop(server_uuid: str, host: str, port: int, server_name: str, introducer_mode=False):
    server_pubkeys[server_uuid] = pub_pem.decode()

    # If not introducer, try to bootstrap
    if not introducer_mode:
        try:
            server_uuid = await bootstrap_with_introducer(
                server_uuid, host, port, public_pem_to_der_b64url(pub_pem)
            )
            if not server_uuid:
                print("[bootstrap] Failed to obtain server ID from introducer.")
                return
            print(f"[bootstrap] Using server ID: {server_uuid}")

        except Exception as e:
            print("[bootstrap] Error:", e)
            return

    async def ws_handler(ws):
        await handle_ws(ws, server_uuid, server_name)

    print(f"[{server_uuid}] Listening on ws://{host}:{port}")
    async with serve(ws_handler, host, port, ping_interval=15, ping_timeout=45):
        # Once server is live, broadcast ANNOUNCE to all peers
        announce_msg = build_server_announce(server_uuid, host, port, public_pem_to_der_b64url(pub_pem))
        for sid, link in list(servers.items()):
            if link and link.open:
                try:
                    await link.send(json.dumps(announce_msg))
                    print(f"[{server_uuid}] Sent SERVER_ANNOUNCE to {sid}")
                except Exception as e:
                    print(f"[{server_uuid}] Failed to announce to {sid}: {e}")
        await asyncio.Future()

# ------------------------------------------------------------
# Program entry point
# ------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOCP Secure Chat Server")
    parser.add_argument("--id", required=False, help="Server ID (UUID v4 preferred)")
    parser.add_argument("--name", required=False, help="Human-friendly server name for UX")
    parser.add_argument("--host", default="127.0.0.1", help="Hostname or IP to bind")
    parser.add_argument("--port", default=8765, type=int, help="TCP port to listen on")
    parser.add_argument("--introducer", action="store_true", help="Run this server as introducer mode")
    args = parser.parse_args()

    # Ensure server UUID v4 (persisted). If --id is a valid v4, use it; else reuse/create one.
    server_uuid = load_or_create_server_uuid(args.id)
    print("uuid: " + server_uuid)

    # Choose a display name (for adverts). Default to first 8 chars of UUID.
    server_name = args.name or f"server-{server_uuid[:8]}"

    try:
        asyncio.run(main_loop(server_uuid, args.host, args.port, server_name, introducer_mode=args.introducer))
    except KeyboardInterrupt:
        print("\nServer shutting down gracefully...")
    except Exception as e:
        import traceback
        print("Fatal error starting server:", e)
        traceback.print_exc()