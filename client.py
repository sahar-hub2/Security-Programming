import asyncio, websockets, json, argparse, base64, time
from keys import generate_rsa4096, rsa_oaep_encrypt, rsa_oaep_decrypt, rsa_pss_sign, rsa_pss_verify

def now_ms(): 
    return int(time.time() * 1000)

async def run_client(user_id: str, server_url: str):
    priv_pem, pub_pem = generate_rsa4096()
    known_pubkeys = {}

    async with websockets.connect(server_url) as ws:
        # --- Register: send our pubkey to server ---
        await ws.send(json.dumps({
            "type": "USER_HELLO",
            "from": user_id,
            "payload": {"pubkey": pub_pem.decode()},  # FIXED: matches server.py
            "to": "*",
            "ts": now_ms()
        }))
        print(f"Connected to {server_url} as {user_id}")

        async def sender():
            while True:
                line = await asyncio.get_event_loop().run_in_executor(None, input)
                if line.startswith("/tell "):
                    parts = line.split(" ", 2)
                    if len(parts) < 3:
                        print("Usage: /tell <user> <message>")
                        continue
                    target, msg = parts[1], parts[2]

                    if target not in known_pubkeys:
                        print(f"No public key for {target}, cannot send encrypted message.")
                        continue

                    ciphertext = rsa_oaep_encrypt(known_pubkeys[target], msg.encode())
                    signature = rsa_pss_sign(priv_pem, ciphertext)

                    await ws.send(json.dumps({
                        "type": "MSG_DIRECT",
                        "from": user_id,
                        "to": target,
                        "ts": now_ms(),
                        "payload": {
                            "ciphertext": base64.b64encode(ciphertext).decode(),
                            "signature": base64.b64encode(signature).decode()
                        }
                    }))
                elif line.strip() == "/list":
                    # Request the server to list users
                    await ws.send(json.dumps({
                        "type": "CMD_LIST",
                        "from": user_id,
                        "to": "*",
                        "ts": now_ms()
                    }))
                
                elif line.startswith("/all "):
                    msg = line[len("/all "):]  # get the message text
                    # Create the broadcast message
                    
                    await ws.send(json.dumps({
                        "type": "MSG_BROADCAST",   
                        "from": user_id,
                        "to": "*",                  
                        "ts": now_ms(),
                        "payload": {
                            "text": msg            
                        }
                    }))
                    
        async def receiver():
            async for raw in ws:
                msg = json.loads(raw)
                mtype = msg.get("type")

                # Store public keys advertised by server
                if mtype == "USER_ADVERTISE":
                    payload = msg.get("payload", {})
                    uid = payload.get("user")
                    pubkey = payload.get("pubkey")
                    if uid and pubkey:
                        known_pubkeys[uid] = pubkey.encode()
                        print(f"[server] learned pubkey for {uid}")

                # Show messages sent directly to us
                elif mtype == "MSG_DIRECT":
                    payload = msg.get("payload", {})
                    ciphertext_b64 = payload.get("ciphertext")
                    signature_b64 = payload.get("signature")
                    sender_uid = msg.get("from")

                    if not ciphertext_b64 or not signature_b64:
                        print(f"[recv] Invalid message from {sender_uid}")
                        continue

                    if sender_uid not in known_pubkeys:
                        print(f"Message from {sender_uid}, but no pubkey known.")
                        continue

                    ciphertext = base64.b64decode(ciphertext_b64)
                    signature = base64.b64decode(signature_b64)

                    # Verify signature
                    if not rsa_pss_verify(known_pubkeys[sender_uid], ciphertext, signature):
                        print(f"[SECURITY] Invalid signature from {sender_uid}!")
                        continue

                    # Decrypt and show message
                    plaintext = rsa_oaep_decrypt(priv_pem, ciphertext).decode()
                    print(f"{sender_uid}: {plaintext}")
                
                # Handle user disconnects
                elif mtype == "USER_REMOVE":
                    payload = msg.get("payload", {})
                    removed_user = payload.get("user")
                    if removed_user:
                        # Remove from known_pubkeys so we don't try to message them
                        known_pubkeys.pop(removed_user, None)
                        print(f"[server] User {removed_user} has disconnected.")
                
                elif mtype == "MSG_BROADCAST":
                    payload = msg.get("payload", {})
                    text = payload.get("text")
                    sender_uid = msg.get("from")
                    if text:
                        print(f"[all] {sender_uid}: {text}")

                # Handle list
                elif mtype == "CMD_LIST_RESULT":
                    payload = msg.get("payload", {})
                    users = payload.get("users", [])
                    print(f"Connected users: {', '.join(users)}")

        await asyncio.gather(sender(), receiver())

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", required=True)
    parser.add_argument("--server", required=True)
    args = parser.parse_args()
    asyncio.run(run_client(args.user, args.server))
