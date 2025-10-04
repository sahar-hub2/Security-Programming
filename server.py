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

Author: Your Group Name
"""

import asyncio, json, argparse, time, websockets, uuid
from websockets.server import serve
from keys import (
    b64url_encode,
    rsa_pss_sign,
    generate_rsa4096,
    public_pem_to_der_b64url,
    der_b64url_to_public_pem,
)
from collections import deque

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
local_users = {}      # user_id -> websocket (connected locally)
user_locations = {}   # user_id -> "local" or server_id (federated)
user_pubkeys = {}     # user_id -> public key PEM string

# ---------------------------------------------------------------------------
# Server identity (ephemeral RSA-4096)
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
async def handle_ws(websocket, server_id):
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
            # 1. USER_HELLO — client registration
            # ================================================================
            if mtype == "USER_HELLO":
                user_id = msg.get("from")
                pubkey_b64u = msg.get("payload", {}).get("pubkey_b64u")

                # --- Validate registration fields ----------------------------
                if not user_id or not pubkey_b64u:
                    error_msg = {
                        "type": "ERROR",
                        "from": server_id,
                        "to": "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {"code": "MISSING_USER_ID_OR_PUBKEY"},
                    }
                    error_msg["sig"] = sign_payload(error_msg["payload"])
                    await websocket.send(json.dumps(error_msg))
                    continue

                # --- Enforce unique username ---------------------------------
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
                print(f"[{server_id}] User {user_id} connected locally.")

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
            # 2. MSG_DIRECT — encrypted private message
            # ================================================================
            elif mtype == "MSG_DIRECT":
                src = msg.get("from")
                dst = msg.get("to")
                payload = msg.get("payload")

                # --- Validate mandatory fields -------------------------------
                if not src or not dst:
                    error_msg = {
                        "type": "ERROR",
                        "from": server_id,
                        "to": src or "*",
                        "id": uuid.uuid4().hex,
                        "ts": now_ms(),
                        "relay": server_id,
                        "payload": {"code": "MISSING_FIELDS"},
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
                        "from": src,          # sender user id
                        "to": dst,
                        "id": mid,            # keep original client id
                        "ts": now_ms(),
                        "relay": server_id,   # transport signer
                        "payload": payload,
                    }
                    deliver["sig"] = sign_payload(deliver["payload"])
                    target_ws = local_users.get(dst)
                    if target_ws:
                        try:
                            await target_ws.send(json.dumps(deliver))
                            print(f"[{server_id}] Delivered message from {src} -> {dst}")
                        except Exception as e:
                            print(f"[{server_id}] Delivery to {dst} failed: {e}")
                continue

            # ================================================================
            # 3. MSG_BROADCAST — public message to all users (system use)
            #    NOTE: Clients now implement E2EE fan-out for '/all'.
            # ================================================================
            elif mtype == "MSG_BROADCAST":
                src = msg.get("from")
                payload = msg.get("payload")
                if not src or not payload or "text" not in payload:
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
                    if uid != src:
                        try:
                            await ws.send(json.dumps(deliver_msg))
                        except Exception as e:
                            print(f"[{server_id}] Broadcast delivery to {uid} failed: {e}")
                print(f"[{server_id}] Broadcast from {src}: {text}")

            # ================================================================
            # 4. CMD_LIST — respond with currently connected users
            # ================================================================
            elif mtype == "CMD_LIST":
                src = msg.get("from")
                if not src:
                    continue
                users_list = sorted(list(local_users.keys()))
                response = {
                    "type": "CMD_LIST_RESULT",
                    "from": server_id,
                    "to": src,
                    "id": uuid.uuid4().hex,
                    "ts": now_ms(),
                    "relay": server_id,
                    "payload": {"users": users_list},
                }
                response["sig"] = sign_payload(response["payload"])
                try:
                    await websocket.send(json.dumps(response))
                except Exception as e:
                    print(f"[{server_id}] Failed to send CMD_LIST_RESULT to {src}: {e}")
                continue

            # ================================================================
            # 5. Unknown or unsupported message type
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
async def main_loop(my_id, host, port):
    """Create WebSocket server and run indefinitely."""
    server_pubkeys[my_id] = pub_pem.decode()

    async def ws_handler(ws):
        await handle_ws(ws, my_id)

    print(f"[{my_id}] About to bind ws://{host}:{port}")

    # v15 pattern: async context + wait forever
    async with serve(ws_handler, host, port, ping_interval=15, ping_timeout=45):
        print(f"[{my_id}] Listening on ws://{host}:{port}")
        await asyncio.Future()  # keep running forever

# ------------------------------------------------------------
# Program entry point
# ------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOCP Secure Chat Server")
    parser.add_argument("--id", required=True, help="Server ID (UUID or name)")
    parser.add_argument("--host", default="127.0.0.1", help="Hostname or IP to bind")
    parser.add_argument("--port", default=8765, type=int, help="TCP port to listen on")
    args = parser.parse_args()

    try:
        asyncio.run(main_loop(args.id, args.host, args.port))
    except KeyboardInterrupt:
        print("\nServer shutting down gracefully...")
    except Exception as e:
        import traceback
        print("Fatal error starting server:", e)
        traceback.print_exc()