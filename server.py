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
from websockets.server import serve
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

# ---------------------------------------------------------------------------
# Main per-connection handler
# ---------------------------------------------------------------------------
async def handle_ws(websocket, server_id: str, server_name: str):
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

# ---------------------------------------------------------------------------
# Main server loop
# ---------------------------------------------------------------------------
async def main_loop(server_uuid: str, host: str, port: int, server_name: str):
    """Create WebSocket server and run indefinitely."""
    # self-advertise (for future federation)
    server_pubkeys[server_uuid] = pub_pem.decode()

    async def ws_handler(ws):
        await handle_ws(ws, server_uuid, server_name)

    print(f"[{server_uuid}] About to bind ws://{host}:{port} (name={server_name})")

    # v15 pattern: async context + wait forever
    async with serve(ws_handler, host, port, ping_interval=15, ping_timeout=45):
        print(f"[{server_uuid}] Listening on ws://{host}:{port}")
        await asyncio.Future()  # keep running forever

# ------------------------------------------------------------
# Program entry point
# ------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOCP Secure Chat Server")
    parser.add_argument("--id", required=False, help="Server ID (UUID v4 preferred)")
    parser.add_argument("--name", required=False, help="Human-friendly server name for UX")
    parser.add_argument("--host", default="127.0.0.1", help="Hostname or IP to bind")
    parser.add_argument("--port", default=8765, type=int, help="TCP port to listen on")
    args = parser.parse_args()

    # Ensure server UUID v4 (persisted). If --id is a valid v4, use it; else reuse/create one.
    server_uuid = load_or_create_server_uuid(args.id)

    # Choose a display name (for adverts). Default to first 8 chars of UUID.
    server_name = args.name or f"server-{server_uuid[:8]}"

    try:
        asyncio.run(main_loop(server_uuid, args.host, args.port, server_name))
    except KeyboardInterrupt:
        print("\nServer shutting down gracefully...")
    except Exception as e:
        import traceback
        print("Fatal error starting server:", e)
        traceback.print_exc()