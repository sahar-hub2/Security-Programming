# server.py
# Minimal SOCP-like messaging server with RSA-signed delivery and USER_ADVERTISE
# Usage: python server.py --id <server_uuid> --host 127.0.0.1 --port 8765

import asyncio, json, argparse, time, websockets
from websockets import serve
from keys import b64url_encode, rsa_pss_sign, generate_rsa4096

# In-memory tables
servers = {}          # server_id -> websocket (federation, not used yet)
server_addrs = {}     # server_id -> (host, port, pubkey_pem)
local_users = {}      # user_id -> websocket
user_locations = {}   # user_id -> "local" or server_id
user_pubkeys = {}     # user_id -> public key PEM (str)

# Ephemeral RSA keys for this server
priv_pem, pub_pem = generate_rsa4096()
server_pubkeys = { }  # server_id -> pubkey_pem

def now_ms():
    return int(time.time() * 1000)

def sign_payload(payload: dict) -> str:
    """
    Returns a base64url-encoded signature of the JSON payload dict.
    """
    import json
    from keys import rsa_pss_sign, b64url_encode
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    return b64url_encode(rsa_pss_sign(priv_pem, payload_bytes))

async def handle_ws(websocket, server_id):
    """
    Handle a single websocket connection from a local user.
    """
    user_id = None
    try:
        async for raw in websocket:
            try:
                msg = json.loads(raw)
            except Exception as e:
                error_msg = {
                    "type": "ERROR",
                    "from": server_id,
                    "to": "*",
                    "ts": now_ms(),
                    "payload": {"code": "BAD_JSON", "detail": str(e)},
                }
                error_msg["sig"] = sign_payload(error_msg["payload"])
                await websocket.send(json.dumps(error_msg))
                continue

            mtype = msg.get("type")

            # --- User registration ---
            if mtype == "USER_HELLO":
                user_id = msg.get("from")
                pubkey = msg.get("payload", {}).get("pubkey")
                if not user_id or not pubkey:
                    error_msg = {
                        "type": "ERROR",
                        "from": server_id,
                        "to": "*",
                        "ts": now_ms(),
                        "payload": {"code": "MISSING_USER_ID_OR_PUBKEY"},
                    }
                    error_msg["sig"] = sign_payload(error_msg["payload"])
                    await websocket.send(json.dumps(error_msg))
                    continue

                if user_id in local_users:
                    error_msg = {
                        "type": "ERROR",
                        "from": server_id,
                        "to": user_id,
                        "ts": now_ms(),
                        "payload": {"code": "NAME_IN_USE", "detail": user_id},
                    }
                    error_msg["sig"] = sign_payload(error_msg["payload"])
                    await websocket.send(json.dumps(error_msg))
                    continue

                local_users[user_id] = websocket
                user_locations[user_id] = "local"
                user_pubkeys[user_id] = pubkey
                print(f"[{server_id}] User {user_id} connected locally.")

                # Send all existing users' pubkeys to the new user
                for uid, pk in user_pubkeys.items():
                    if uid != user_id:
                        advertise_msg = {
                            "type": "USER_ADVERTISE",
                            "from": server_id,
                            "to": user_id,
                            "ts": now_ms(),
                            "payload": {"user": uid, "pubkey": pk}
                        }
                        advertise_msg["sig"] = sign_payload(advertise_msg["payload"])
                        await websocket.send(json.dumps(advertise_msg))
                
                # Send server's own USER_ADVERTISE to the new user
                server_advertise = {
                    "type": "USER_ADVERTISE",
                    "from": server_id,
                    "to": user_id,
                    "ts": now_ms(),
                    "payload": {"user": server_id, "pubkey": pub_pem.decode()}
                }
                server_advertise["sig"] = sign_payload(server_advertise["payload"])
                await websocket.send(json.dumps(server_advertise))

                # Broadcast this user's pubkey to all other local users
                advertise_msg = {
                    "type": "USER_ADVERTISE",
                    "from": server_id,
                    "to": "*",
                    "ts": now_ms(),
                    "payload": {"user": user_id, "pubkey": pubkey}
                }
                advertise_msg["sig"] = sign_payload(advertise_msg["payload"])
                
                for uid, ws in local_users.items():
                    if ws != websocket:
                        try:
                            await ws.send(json.dumps(advertise_msg))
                        except Exception as e:
                            print(f"[{server_id}] Failed to advertise {user_id} to {uid}: {e}")
                continue

            # --- Direct messaging ---
            elif mtype == "MSG_DIRECT":
                src = msg.get("from")
                dst = msg.get("to")
                payload = msg.get("payload")

                if not src or not dst:
                    error_msg = {
                        "type": "ERROR",
                        "from": server_id,
                        "to": src or "*",
                        "ts": now_ms(),
                        "payload": {"code": "MISSING_FIELDS"},
                    }
                    error_msg["sig"] = sign_payload(error_msg["payload"])
                    await websocket.send(json.dumps(error_msg))
                    continue

                loc = user_locations.get(dst)
                if loc is None:    
                    error_msg = {
                        "type": "ERROR",
                        "from": server_id,
                        "to": src,
                        "ts": now_ms(),
                        "payload": {"code": "USER_NOT_FOUND", "detail": dst},
                    }
                    error_msg["sig"] = sign_payload(error_msg["payload"])
                    await websocket.send(json.dumps(error_msg))
                    continue

                if loc == "local":
                    deliver = {
                        "type": "USER_DELIVER",
                        "from": src,
                        "to": dst,
                        "ts": now_ms(),
                        "payload": payload,
                    }
                    # sign payload
                    deliver["sig"] = b64url_encode(
                        rsa_pss_sign(
                            priv_pem,
                            json.dumps(deliver["payload"], sort_keys=True).encode(),
                        )
                    )
                    target_ws = local_users.get(dst)
                    if target_ws:
                        try:
                            await target_ws.send(json.dumps(deliver))
                            print(f"[{server_id}] Delivered message from {src} -> {dst}")
                        except Exception as e:
                            print(f"[{server_id}] Delivery to {dst} failed: {e}")
                continue
            
            elif mtype == "MSG_BROADCAST":
                src = msg.get("from")
                payload = msg.get("payload")
                if not src or not payload or "text" not in payload:
                    continue
                text = payload["text"]
                # Prepare delivery to all local users except sender
                deliver_msg = {
                    "type": "USER_DELIVER",
                    "from": src,
                    "to": "*",
                    "ts": now_ms(),
                    "payload": {"text": text},
                }
                deliver_msg["sig"] = sign_payload(deliver_msg["payload"])
                for uid, ws in local_users.items():
                    if uid != src:  # don’t send back to sender
                        try:
                            await ws.send(json.dumps(deliver_msg))
                        except Exception as e:
                            print(f"[{server_id}] Broadcast delivery to {uid} failed: {e}")
                print(f"[{server_id}] Broadcast from {src}: {text}")
                
            # --- List connected users ---
            elif mtype == "CMD_LIST":
                src = msg.get("from")
                if not src:
                    continue
                users_list = list(local_users.keys())   
                response = {
                    "type": "CMD_LIST_RESULT",
                    "from": server_id,
                    "to": src,
                    "ts": now_ms(),
                    "payload": {"users": users_list}
                }
                response["sig"] = sign_payload(response["payload"])
                
                try:
                    await websocket.send(json.dumps(response))
                except Exception as e:
                    print(f"[{server_id}] Failed to send CMD_LIST_RESULT to {src}: {e}")
                continue

            # Unknown message
            else:
                print(f"[{server_id}] Unknown msg type: {mtype}")

    except websockets.exceptions.ConnectionClosedOK:
        print(f"[{server_id}] WebSocket closed normally for {user_id}")
    except Exception as e:
        print(f"[{server_id}] recv_loop error: {e}")
    finally:
        # Only clean up if websocket is actually closed
        if user_id and websocket.close_code is not None:
            local_users.pop(user_id, None)
            user_locations.pop(user_id, None)
            user_pubkeys.pop(user_id, None)
            print(f"[{server_id}] User {user_id} disconnected and cleaned up.")
            
            # Broadcast USER_REMOVE to all remaining local users
            remove_msg = {
                "type": "USER_REMOVE",
                "from": server_id,
                "to": "*",
                "ts": now_ms(),
                "payload": {"user": user_id}
            }
            remove_msg["sig"] = sign_payload(remove_msg["payload"])
            
            for uid, ws in local_users.items():
                try:
                    await ws.send(json.dumps(remove_msg))
                except Exception as e:
                    print(f"[{server_id}] Failed to send USER_REMOVE to {uid}: {e}")
                    
async def main_loop(my_id, host, port):
    server_pubkeys[my_id] = pub_pem.decode()  # self-advertise
    async def ws_handler(ws):
        await handle_ws(ws, my_id)

    server = await serve(ws_handler, host=host, port=port)
    print(f"[{my_id}] Listening on ws://{host}:{port}")
    await server.wait_closed()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True, help="Server ID (UUID or name)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8765, type=int)
    args = parser.parse_args()

    try:
        asyncio.run(main_loop(args.id, args.host, args.port))
    except KeyboardInterrupt:
        print("Server shutting down...")

