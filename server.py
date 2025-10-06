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
     "pubkey": "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA8F2eeTpQ3mnxppyr8kmaaK-3G8PB1728lyn9lXFhbYXJiZ7BDpsV3RSIlVA0ewtW_U7goGsVZhf4lwZEjeVnqqUFbheXXlMtCOO4BzPgpPD6PtHnXvIv8EMyQP8gXJLm9zQb1KR9mvKwRYqretNB504DNGyjpdsUpw7lkjYv4RvJdFsskvftWut-coGoJAAPDm8cskOAT2oHPPlhDmIkfK6HypUNE_2RMJIDlkzbCTuPsHRcrXjur-GLjAfFfILphn1BDV5sF1kEZz1oKQOIeSYk7fD-eiUSjr5i_ypXXwKlhM96THLJvTG7X2GYtoGwBNM1jXOMk8C5cq9T5myCLfv5iZC7mGMKIQKDv9J_AV-3b1GGc7Y-NYTfHpHOLm9gVdb9MUw9tPz5JXf1jXSnT95zGxGM2HDwOyEIssYpv_FjMFqBJNqwzNlUnfqtHnAaAUgRcKzUieFPEGBz6iyfrzoBoyuPtxGu84Bd-VBarPiFczGC_zR7v6pPRAMcqUHgR2M3uHT4smWCuC_QTW5-KVtsVNHK57aS_5q46fo2dfS_CcYsyWfXel6wmRtlrQbi1KmvgZQxaIjOLSQaVm8ezpXjg1S_lX-TWnBZCNc4Dnfn8a3wo4NlRd0NVhJnGOC4x5v4nYEF3kQ0ETm2kCF485p0dn5u5xy1M5Fg9-9gg-UCAwEAAQ"},
    # {"host": "127.0.0.1", "port": 9002,
    #  "pubkey": "BASE64URL_OF_INTRODUCER_PUBKEY"},
]

def is_open(ws):
    """Return True if websocket connection is alive across websocket versions."""
    if not ws:
        return False
    try:
        # websockets <=10.x
        if hasattr(ws, "open"):
            return bool(ws.open)
        if hasattr(ws, "closed"):
            return not ws.closed
        # websockets >=12.x (ClientConnection)
        if hasattr(ws, "state"):
            return getattr(ws.state, "name", "").upper() == "OPEN"
    except Exception:
        return False
    return False

def is_introducer(host: str, port: int) -> bool:
    """Return True if (host, port) matches a known introducer from the bootstrap list."""
    for entry in bootstrap_servers:
        if entry["host"] == host and int(entry["port"]) == int(port):
            return True
    return False

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
# Server identity (persistent RSA-4096 for transport signing)
# ---------------------------------------------------------------------------
priv_pem = None
pub_pem  = None
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
    # print(f"server key: {priv_pem}")
    return b64url_encode(rsa_pss_sign(priv_pem, payload_bytes))

def build_server_hello_join(my_id, host, port, pubkey_b64u):
    return {
        "type": "SERVER_HELLO_JOIN",
        "from": my_id,
        "id": uuid.uuid4().hex,
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
        "id": uuid.uuid4().hex,
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
# Presence Sync Helper (for newly connected servers)
# ---------------------------------------------------------------------------
def build_presence_sync(server_id):
    """
    Build a SERVER_PRESENCE_SYNC message containing all locally known users.
    Each payload entry also includes the sender server_id for context.
    """
    entries = []
    for uid, loc in user_locations.items():
        if loc == "local" and uid in user_pubkeys:
            entries.append({
                "user_id": uid,
                "server_id": server_id,  # who hosts this user
                "meta": {"name": user_names.get(uid, uid)},
                "pubkey": public_pem_to_der_b64url(user_pubkeys[uid].encode()),
            })

    payload = {
        "server_id": server_id,  # <— include the sender id inside payload
        "users": entries,
    }

    return {
        "type": "SERVER_PRESENCE_SYNC",
        "from": server_id,
        "id": uuid.uuid4().hex,   # <— unique message id, not server id
        "to": "*",
        "ts": now_ms(),
        "payload": payload,
        "sig": sign_payload(payload),
    }


# ---------------------------------------------------------------------------
# Main per-connection handler
# ---------------------------------------------------------------------------
async def bootstrap_with_introducer(my_id, host, port, pubkey_b64u):
    """Join the SOCP network via an introducer, verifying its signature."""
    last_err = None
    introducer_hosts = {(b["host"], b["port"]) for b in bootstrap_servers}

    for entry in bootstrap_servers:
        introducer_host, introducer_port = entry["host"], entry["port"]
        introducer_pub_b64u = entry["pubkey"]
        introducer_uri = f"ws://{introducer_host}:{introducer_port}"

        try:
            async with websockets.connect(introducer_uri, ping_interval=15, ping_timeout=45) as ws:
                # 👇 Corrected: use *our* host/port (not introducer’s)
                join_msg = build_server_hello_join(my_id, host, port, pubkey_b64u)
                join_msg["to"] = f"{introducer_host}:{introducer_port}"  # per spec
                await ws.send(json.dumps(join_msg))

                raw = await ws.recv()
                msg = json.loads(raw)
                if msg.get("type") != "SERVER_WELCOME":
                    raise RuntimeError("Unexpected response during bootstrap")

                # ✅ Verify introducer signature with pinned key
                intro_pub_pem = der_b64url_to_public_pem(introducer_pub_b64u)
                payload = msg.get("payload", {}) or {}
                sig_ok = rsa_pss_verify(
                    intro_pub_pem,
                    json.dumps(payload, sort_keys=True).encode(),
                    b64url_decode(msg.get("sig", "")),
                )
                if not sig_ok:
                    raise RuntimeError("SERVER_WELCOME signature failed (introducer not trusted)")

                assigned_id = payload.get("assigned_id")
                if not assigned_id:
                    raise RuntimeError("SERVER_WELCOME missing assigned_id")

                # ✅ Import known servers, but skip introducer entries
                for s in payload.get("servers", []):
                    sid, h, p, pk = s["server_id"], s["host"], s["port"], s["pubkey"]
                    if (h, p) in introducer_hosts:
                        print(f"[bootstrap] Skipping introducer {h}:{p} from peer list.")
                        continue
                    server_addrs[sid] = (h, p, pk)
                    servers[sid] = None

                # ✅ Import known clients from introducer (for awareness)
                for c in payload.get("clients", []):
                    uid = c.get("user_id")
                    pk_b64u = c.get("pubkey")
                    if not uid or not pk_b64u:
                        continue
                    try:
                        user_pubkeys[uid] = der_b64url_to_public_pem(pk_b64u).decode()
                        user_locations[uid] = "remote"
                    except Exception:
                        pass

                print(f"[bootstrap] OK via {introducer_uri} → assigned_id={assigned_id}")
                print(f"[bootstrap] Known servers after join: {server_addrs}")
                return assigned_id

        except Exception as e:
            last_err = e
            print(f"[bootstrap] Failed via {introducer_uri}: {e}")
            continue

    raise RuntimeError(f"Could not connect to any introducer: {last_err}")


async def handle_ws(websocket, server_id: str, server_name: str):
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
            except Exception as e:
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
                # --- Gossip payload now includes the user's public key ---
                gossip_payload = {
                    "user_id": user_id,
                    "server_id": server_id,
                    "meta": {"name": user_names.get(user_id, user_id)},
                    "pubkey": public_pem_to_der_b64url(pubkey_pem),  # ✅ include key
                }

                gossip_msg = {
                    "type": "USER_ADVERTISE",
                    "from": server_id,
                    "to": "*",
                    "id": uuid.uuid4().hex,
                    "ts": now_ms(),
                    "payload": gossip_payload,
                }
                gossip_msg["sig"] = sign_payload(gossip_payload)

                for sid, link in list(servers.items()):
                    if is_open(link):
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
                        "id": uuid.uuid4().hex,
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
                # Show all known users (local + remote we learned)
                users_list = sorted(list(user_pubkeys.keys()))
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
                        "names": names_map,
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
                peer_id = msg["from"]
                if peer_id not in servers:
                    servers[peer_id] = websocket
                    print(f"[federation] Accepted inbound connection from server {peer_id}")
                
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
                
                # --- Establish reverse federation link ---
                peer_uri = f"ws://{host}:{port}"
                try:
                    peer_ws = await websockets.connect(peer_uri)
                    servers[assigned_id] = peer_ws
                    print(f"[federation] Connected back to new peer {assigned_id} at {peer_uri}")
                    
                    # --- Advertise the peer server's key to local clients (so they can verify relayed messages) ---
                    advertise_peer = {
                        "type": "USER_ADVERTISE",
                        "from": server_id,
                        "to": "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {
                            "user": assigned_id,  # the peer server’s UUID
                            "name": f"server-{assigned_id[:8]}",
                            "pubkey_b64u": pubkey_b64u,
                        },
                    }
                    advertise_peer["sig"] = sign_payload(advertise_peer["payload"])

                    for luid, ws in list(local_users.items()):
                        try:
                            await ws.send(json.dumps(advertise_peer))
                            print(f"[announce] Sent USER_ADVERTISE (server peer {assigned_id}) to local client {luid}")
                        except Exception:
                            pass

                    
                    # --- Immediately share local presence with the new peer ---
                    presence_msg = build_presence_sync(server_id)
                    try:
                        await peer_ws.send(json.dumps(presence_msg))
                        print(f"[federation] Sent presence sync ({len(presence_msg['payload']['users'])} users) to {assigned_id}")
                    except Exception as e:
                        print(f"[federation] Failed to send presence sync to {assigned_id}: {e}")

                except Exception as e:
                    print(f"[federation] Failed to connect back to {assigned_id} ({peer_uri}): {e}")

                # Prepare SERVER_WELCOME response (per §8.1 — include clients list)
                welcome_payload = {
                    "assigned_id": assigned_id,
                    "servers": [
                        {"server_id": sid, "host": h, "port": p, "pubkey": pk}
                        for sid, (h, p, pk) in server_addrs.items()
                    ],
                    "clients": [
                        {
                            "user_id": uid,
                            "host": host,
                            "port": port,
                            "pubkey": public_pem_to_der_b64url(user_pubkeys[uid].encode()),
                        }
                        for uid in list(local_users.keys())
                        if uid in user_pubkeys
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
                print(f"[introducer] Sent SERVER_WELCOME with {len(welcome_payload['clients'])} clients.")
                return

            elif mtype == "SERVER_ANNOUNCE":
                payload = msg.get("payload", {}) or {}
                new_sid = msg.get("from")
                host = payload.get("host")
                port = payload.get("port")
                pubkey_b64u = payload.get("pubkey")
                
                # Store inbound federation connections automatically
                peer_id = msg["from"]
                if peer_id not in servers:
                    servers[peer_id] = websocket
                    print(f"[federation] Accepted inbound connection from server {peer_id}")

                # Validate
                if not new_sid or not host or not port or not pubkey_b64u:
                    print("[announce] Invalid SERVER_ANNOUNCE payload")
                    return

                # Verify signature using the announcer's public key (from payload)
                try:
                    announcer_pub_pem = der_b64url_to_public_pem(pubkey_b64u)
                    sig_ok = rsa_pss_verify(announcer_pub_pem, json.dumps(payload, sort_keys=True).encode(), b64url_decode(msg.get("sig")))
                except Exception as e:
                    print(f"[announce] Failed to verify signature from {new_sid}: {e}")
                    return

                if not sig_ok:
                    print(f"[announce] BAD SIGNATURE from {new_sid}, ignoring")
                    return

                # Register the server
                server_addrs[new_sid] = (host, port, pubkey_b64u)
                print(f"[announce] Registered new server {new_sid} at {host}:{port}")
                
                # --- Establish reverse federation link ---
                peer_uri = f"ws://{host}:{port}"
                try:
                    peer_ws = await websockets.connect(peer_uri)
                    servers[new_sid] = peer_ws
                    print(f"[federation] Connected back to new peer {new_sid} at {peer_uri}")
                    
                    # --- Advertise the peer server's key to local clients (so they can verify relayed messages) ---
                    advertise_peer = {
                        "type": "USER_ADVERTISE",
                        "from": server_id,
                        "to": "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {
                            "user": new_sid,
                            "name": f"server-{new_sid[:8]}",
                            "pubkey_b64u": pubkey_b64u,
                        },
                    }
                    advertise_peer["sig"] = sign_payload(advertise_peer["payload"])

                    for luid, ws in list(local_users.items()):
                        try:
                            await ws.send(json.dumps(advertise_peer))
                            print(f"[announce] Sent USER_ADVERTISE (server peer {new_sid}) to local client {luid}")
                        except Exception:
                            pass

                    
                    presence_msg = build_presence_sync(server_id)
                    try:
                        await peer_ws.send(json.dumps(presence_msg))
                        print(f"[federation] Sent presence sync ({len(presence_msg['payload']['users'])} users) to {new_sid}")
                    except Exception as e:
                        print(f"[federation] Failed to send presence sync to {new_sid}: {e}")

                except Exception as e:
                    print(f"[federation] Failed to connect back to {new_sid} ({peer_uri}): {e}")

            elif mtype == "USER_ADVERTISE":
                payload = msg.get("payload", {})
                uid = payload.get("user_id")
                origin_sid = payload.get("server_id")

                # Verify signature using sender server pubkey
                sig_b64u = msg.get("sig")
                if not sig_b64u or origin_sid not in server_addrs:
                    return
                pubkey_b64u = server_addrs[origin_sid][2]
                origin_pub_pem = der_b64url_to_public_pem(pubkey_b64u)
                if not rsa_pss_verify(origin_pub_pem, json.dumps(payload, sort_keys=True).encode(), b64url_decode(sig_b64u)):
                    print(f"[gossip] BAD SIGNATURE in USER_ADVERTISE from {origin_sid}")
                    return

                # Update mapping
                user_locations[uid] = origin_sid
                print(f"[gossip] Learned user {uid} is on server {origin_sid}")

                # --- Store the remote user's public key, if provided ---
                if "pubkey" in payload and payload["pubkey"]:
                    try:
                        user_pub_pem = der_b64url_to_public_pem(payload["pubkey"])
                        user_pubkeys[uid] = user_pub_pem.decode()
                        print(f"[gossip] Stored pubkey for remote user {uid}")
                    except Exception as e:
                        print(f"[gossip] Failed to decode pubkey for {uid}: {e}")

                # --- Notify all local clients about this remote user ---
                user_name = payload.get("meta", {}).get("name", uid)
                user_names[uid] = user_name
                pubkey_b64u = payload.get("pubkey")

                # Build a new, locally signed advert for our clients
                advertise_payload = {
                    "user": uid,
                    "name": user_name,
                    "pubkey_b64u": pubkey_b64u,
                }
                local_advert = {
                    "type": "USER_ADVERTISE",
                    "from": server_id,
                    "to": "*",
                    "id": uuid.uuid4().hex,
                    "ts": now_ms(),
                    "relay": server_id,  # signer = this server (local)
                    "payload": advertise_payload,
                }

               # Sign with this server’s transport key (canonical signing helper)
                local_advert["sig"] = sign_payload(advertise_payload)

                # Send to all local clients
                for luid, ws in list(local_users.items()):
                    try:
                        await ws.send(json.dumps(local_advert))
                        print(f"[gossip] Announced remote user {uid} to local client {luid}")
                    except Exception as e:
                        print(f"[gossip] Failed to announce remote user {uid} to {luid}: {e}")



                # --- Forward the original frame verbatim to other servers ---
                for sid, link in list(servers.items()):
                    if sid == origin_sid:  # don't bounce back to the source
                        continue
                    if not is_open(link):
                        continue
                    try:
                        await link.send(json.dumps(msg))  # send unmodified frame
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
                origin_srv_pub_pem = der_b64url_to_public_pem(pubkey_b64u)
                if not rsa_pss_verify(
                    origin_srv_pub_pem,
                    json.dumps(payload, sort_keys=True).encode(),
                    b64url_decode(sig_b64u),
                ):
                    print(f"[gossip] BAD SIGNATURE in USER_REMOVE from {origin_sid}")
                    return

                # --- Single removal + mark changed ---
                removed_name = user_names.get(uid, uid)  # keep for UX/logs
                changed = False
                if user_locations.get(uid) == origin_sid:
                    user_locations.pop(uid, None)
                    user_pubkeys.pop(uid, None)
                    user_names.pop(uid, None)
                    changed = True
                    print(f"[gossip] Removed user {uid} from server {origin_sid}")

                # --- Tell *local* clients so they log the leave and update their lists ---
                if changed:
                    local_remove = {
                        "type": "USER_REMOVE",
                        "from": server_id,
                        "to": "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {"user": uid, "name": removed_name},
                    }
                    local_remove["sig"] = sign_payload(local_remove["payload"])
                    for luid, ws in list(local_users.items()):
                        try:
                            await ws.send(json.dumps(local_remove))
                        except Exception:
                            pass

                    # Optional: push a fresh /list snapshot
                    users_list = sorted(list(user_pubkeys.keys()))
                    names_map = {u: user_names.get(u, u) for u in users_list}
                    list_result = {
                        "type": "CMD_LIST_RESULT",
                        "from": server_id,
                        "to": "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {"users": users_list, "names": names_map},
                    }
                    list_result["sig"] = sign_payload(list_result["payload"])
                    for luid, ws in list(local_users.items()):
                        try:
                            await ws.send(json.dumps(list_result))
                        except Exception:
                            pass

                # --- Keep federating (avoid bouncing back to the sender socket) ---
                for sid, link in list(servers.items()):
                    if link == websocket:
                        continue
                    if not is_open(link):
                        continue
                    try:
                        await link.send(json.dumps(msg))
                    except Exception as e:
                        print(f"[gossip] Failed to forward USER_REMOVE to {sid}: {e}")
                payload = msg.get("payload", {})
                uid = payload.get("user_id")
                origin_sid = payload.get("server_id")

                sig_b64u = msg.get("sig")
                if not sig_b64u or origin_sid not in server_addrs:
                    return
                pubkey_b64u = server_addrs[origin_sid][2]
                origin_srv_pub_pem = der_b64url_to_public_pem(pubkey_b64u)
                if not rsa_pss_verify(origin_srv_pub_pem, json.dumps(payload, sort_keys=True).encode(), b64url_decode(sig_b64u)):
                    print(f"[gossip] BAD SIGNATURE in USER_REMOVE from {origin_sid}")
                    return
                


                if user_locations.get(uid) == origin_sid:
                    user_locations.pop(uid, None)
                    user_pubkeys.pop(uid, None)   
                    user_names.pop(uid, None)     
                    print(f"[gossip] Removed user {uid} from server {origin_sid}")

                 # Remove all state for that user if we mapped them to that origin
                changed = False
                if user_locations.get(uid) == origin_sid:
                    user_locations.pop(uid, None)
                    user_pubkeys.pop(uid, None)
                    user_names.pop(uid, None)
                    changed = True
                    print(f"[gossip] Removed user {uid} from server {origin_sid}")

                # ✅ Notify all *local* clients so their UIs/logs update
                if changed:
                    local_remove = {
                        "type": "USER_REMOVE",
                        "from": server_id,
                        "to": "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {"user": uid},   # matches what you send on local disconnects
                    }
                    local_remove["sig"] = sign_payload(local_remove["payload"])
                    for luid, ws in list(local_users.items()):
                        try:
                            await ws.send(json.dumps(local_remove))
                        except Exception:
                            pass

                    # (optional) also push a refreshed /list snapshot for UX
                    users_list = sorted(list(user_pubkeys.keys()))
                    names_map = {u: user_names.get(u, u) for u in users_list}
                    list_result = {
                        "type": "CMD_LIST_RESULT",
                        "from": server_id,
                        "to": "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {"users": users_list, "names": names_map},
                    }
                    list_result["sig"] = sign_payload(list_result["payload"])
                    for luid, ws in list(local_users.items()):
                        try:
                            await ws.send(json.dumps(list_result))
                        except Exception:
                            pass

                

                # Forward to others
                for sid, link in list(servers.items()):
                    if link == websocket:
                        continue
                    if not is_open(link):          
                        continue
                    try:
                        await link.send(json.dumps(msg))
                    except Exception as e:
                        print(f"[gossip] Failed to forward USER_REMOVE to {sid}: {e}")
            
            elif mtype == "SERVER_DELIVER":
                payload = msg.get("payload", {}) or {}
                recipient = payload.get("user_id")
                sender = payload.get("sender")
                sender = payload.get("sender")

                # Verify signature from the sending server
                sig_b64u = msg.get("sig")
                origin_sid = msg.get("from")
                to_sid = msg.get("to")
                if not sig_b64u or origin_sid not in server_addrs:
                    print(f"[{server_id}] SERVER_DELIVER missing sig or unknown origin")
                    return

                print(f"origin_sid: {origin_sid}")
                pubkey_b64u = server_addrs[origin_sid][2]
                origin_srv_pub_pem = der_b64url_to_public_pem(pubkey_b64u)
                if not rsa_pss_verify(origin_srv_pub_pem, json.dumps(payload, sort_keys=True).encode(), b64url_decode(sig_b64u)):
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
                    if target_sid and target_sid in servers and is_open(servers[target_sid]):
                        try:
                            await servers[target_sid].send(json.dumps(msg))
                            print(f"[{server_id}] Forwarded SERVER_DELIVER for {recipient} to {target_sid}")
                        except Exception as e:
                            print(f"[{server_id}] Failed to forward SERVER_DELIVER to {target_sid}: {e}")
                    else:
                        print(f"[{server_id}] Unknown location for {recipient}, dropping SERVER_DELIVER.")

            elif mtype == "SERVER_PRESENCE_SYNC":
                payload = msg.get("payload", {})
                origin_sid = payload.get("server_id") or msg.get("from")
                sig_b64u = msg.get("sig")

                print(f"origin sid: {origin_sid}")
                print(f"known server: {server_addrs}")
                # --- Verify signature using sender server pubkey ---
                if not sig_b64u or origin_sid not in server_addrs:
                    print(f"[sync] Missing sig or unknown origin for SERVER_PRESENCE_SYNC")
                    return

                pubkey_b64u = server_addrs[origin_sid][2]
                print(f"origin_sid: {origin_sid}")
                origin_srv_pub_pem = der_b64url_to_public_pem(pubkey_b64u)
                if not rsa_pss_verify(
                    origin_srv_pub_pem,
                    json.dumps(payload, sort_keys=True).encode(),
                    b64url_decode(sig_b64u),
                ):
                    print(f"[sync] BAD SIGNATURE in SERVER_PRESENCE_SYNC from {origin_sid}")
                    return

                # --- Import user entries only; DO NOT re-advertise ---
                count = 0
                for u in payload.get("users", []):
                    uid = u.get("user_id")
                    sid = u.get("server_id") or origin_sid
                    pk_b64u = u.get("pubkey")
                    if not uid or not sid or not pk_b64u:
                        continue
                    try:
                        user_pubkeys[uid] = der_b64url_to_public_pem(pk_b64u).decode()
                        user_locations[uid] = sid
                        user_names[uid] = u.get("meta", {}).get("name", uid)
                        count += 1
                    except Exception as e:
                        print(f"[sync] Failed to import {uid}: {e}")
                print(f"[sync] Imported {count} users from {origin_sid}")
                
                # --- Notify local clients (optional UX refresh) ---
                if count > 0:
                    users_list = sorted(list(user_pubkeys.keys()))
                    names_map = {uid: user_names.get(uid, uid) for uid in users_list}
                    list_result = {
                        "type": "CMD_LIST_RESULT",
                        "from": server_id,
                        "to": "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {"users": users_list, "names": names_map},
                    }
                    list_result["sig"] = sign_payload(list_result["payload"])
                    for luid, ws in list(local_users.items()):
                        try:
                            await ws.send(json.dumps(list_result))
                        except Exception:
                            pass



            # ==========================================F======================
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
            # capture name BEFORE popping state
            removed_name = user_names.get(user_id, user_id)


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
                "payload": {"user": user_id, "name": removed_name},
            }
            remove_msg["sig"] = sign_payload(remove_msg["payload"])
            for uid, ws in list(local_users.items()):
                try:
                    await ws.send(json.dumps(remove_msg))
                except Exception as e:
                    print(f"[{server_id}] Failed to send USER_REMOVE to {uid}: {e}")
            # --- Gossip USER_REMOVE to all known servers -------------------
            gossip_payload = {"user_id": user_id, "server_id": server_id, "name": removed_name} 
            gossip_msg = {
                "type": "USER_REMOVE",
                "from": server_id,
                "to": "*",
                "ts": now_ms(),
                "id": uuid.uuid4().hex, 
                "payload": gossip_payload,
            }
            gossip_msg["sig"] = sign_payload(gossip_payload)

            for sid, link in list(servers.items()):
                if not is_open(link):           # ✅ version-safe
                    continue
                try:
                    await link.send(json.dumps(gossip_msg))
                    print(f"[{server_id}] Gossiped USER_REMOVE for {user_id} to {sid}")
                except Exception as e:
                    print(f"[{server_id}] Gossip remove failed to {sid}: {e}")

async def connect_to_known_servers(my_id, host, port):
    for sid, (h, p, pk_b64u) in server_addrs.items():
        # Skip self and introducers
        if sid == my_id or is_introducer(h, p):
            continue

        uri = f"ws://{h}:{p}"
        try:
            ws = await websockets.connect(uri, ping_interval=15, ping_timeout=45)
            servers[sid] = ws
            print(f"[federation] Connected to peer {sid} at {uri}")
            # Send SERVER_ANNOUNCE so the peer registers us
            announce = build_server_announce(my_id, host, port, public_pem_to_der_b64url(pub_pem))
            await ws.send(json.dumps(announce))
        except Exception as e:
            print(f"[federation] Failed to connect to {sid} ({uri}): {e}")

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
            
            # Establish outgoing connections to all known servers
            await connect_to_known_servers(server_uuid, host, port)


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
            if is_open(link):
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
    server_uuid = load_or_create_server_uuid(args.id, name=args.name)

    # Choose a display name (for adverts). Default to first 8 chars of UUID.
    server_name = args.name or f"server-{server_uuid[:8]}"

    # NEW: persist keys for this server (introducer or not)
    from keys import load_or_create_keys, public_pem_to_der_b64url
    priv_pem, pub_pem = load_or_create_keys(server_name)   # e.g., .keys/server-xxxx.priv.pem
    print(f"[keys] Loaded keys for {server_name} → .keys/{server_name}.priv.pem / .pub.pem")

    try:
        asyncio.run(main_loop(server_uuid, args.host, args.port, server_name, introducer_mode=args.introducer))
    except KeyboardInterrupt:
        print("\nServer shutting down gracefully...")
    except Exception as e:
        import traceback
        print("Fatal error starting server:", e)
        traceback.print_exc()