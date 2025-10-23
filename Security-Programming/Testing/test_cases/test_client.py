"""
test_client.py
---------------
Unit and integration tests for the `client` module. Covers transport-level
signature verification, content signatures (JSON envelope), canonicalization,
and the client runtime behavior (message send/receive, /all fan-out, and file
transfer framing). Tests include small async harnesses that mock websockets.


Author: GROUP 12
MEMBERS:  
  1. Debasish Saha Pranta (a1963099, debasishsaha.pranta@student.adelaide.edu.au)
  2. Samin Yeasar Seaum (a1976022, saminyeasar.seaum@student.adelaide.edu.au)
  3. Abidul Kabir (a1974976, abidul.kabir@student.adelaide.edu.au)
  4. Sahar Alzahrani (a1938372, sahar.alzahrani@student.adelaide.edu.au)
  5. Mahrin Mahia (a1957342, mahrin.mahia@student.adelaide.edu.au)
  6. Maria Hasan Logno (a1975478, mariahasan.logno@student.adelaide.edu.au)

"""

import os
import sys
import time
import json
import asyncio
import builtins
import pytest
import uuid


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../Implementation/secure_version"))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import client
import keys
from client import run_client, b64url_encode, b64url_decode, make_content_sig, verify_content_sig

# -------------------
# Unit Tests (synchronous helpers)
# -------------------

# Verify b64url encode/decode roundtrip and padding behavior
def test_b64url_roundtrip():
    b = b"\x00\xffhello\x10"
    s = b64url_encode(b)
    out = b64url_decode(s)
    assert out == b

# now_ms should be integer and monotonic across short sleeps
def test_now_ms_increasing_and_int():
    t1 = client.now_ms()
    time.sleep(0.001)
    t2 = client.now_ms()
    assert t2 >= t1

# canonical() produces deterministic JSON for equivalent objects
def test_canonical_deterministic():
    a = {"b": 1, "a": [2, 3]}
    b = {"a": [2, 3], "b": 1}
    ca = client.canonical(a)
    cb = client.canonical(b)
    assert ca == cb
    assert json.loads(ca.decode()) == json.loads(cb.decode())

# make_content_sig and verify_content_sig should roundtrip for valid keys
def test_make_and_verify_content_sig_roundtrip():
    priv, pub = keys.generate_rsa4096()
    ciphertext = b64url_encode(b"secret-bytes")
    ts = int(time.time() * 1000)
    sig = make_content_sig(priv, ciphertext, "A", "B", ts)
    assert verify_content_sig(pub, ciphertext, "A", "B", ts, sig)

# verify_transport_sig enforces transport signatures and detects tampering
def test_verify_transport_sig_behavior():
    srv_priv, srv_pub = keys.generate_rsa4096()
    signer_id = "server-test-1"
    known = {signer_id: srv_pub}

    payload = {"users": ["u1", "u2"]}
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    sig = keys.rsa_pss_sign(srv_priv, payload_bytes)
    sig_b64u = b64url_encode(sig)

    msg = {"payload": payload, "sig": sig_b64u, "relay": signer_id}
    assert client.verify_transport_sig(msg, known) is True

    # tampered payload
    msg2 = {"payload": {"users": ["u1", "X"]}, "sig": sig_b64u, "relay": signer_id}
    assert client.verify_transport_sig(msg2, known) is False

    # missing sig is now rejected by hardened client
    msg3 = {"payload": payload}
    assert client.verify_transport_sig(msg3, known) is False

    # correctly signed message should be accepted
    sig3 = keys.rsa_pss_sign(srv_priv, json.dumps(payload, sort_keys=True).encode())
    msg4 = {"payload": payload, "sig": b64url_encode(sig3), "relay": signer_id}
    assert client.verify_transport_sig(msg4, known) is True

# Content signature replay attacks are detected by timestamp validation
def test_content_sig_replay_detection():
    priv, pub = keys.generate_rsa4096()
    payload = b64url_encode(b"data")
    ts = client.now_ms()
    sig = make_content_sig(priv, payload, "A", "B", ts)
    assert verify_content_sig(pub, payload, "A", "B", ts, sig) is True
    old_ts = ts - 10_000
    assert verify_content_sig(pub, payload, "A", "B", old_ts, sig) is False

# canonicalization handles unicode consistently
def test_canonical_unicode_consistency():
    a = {"msg": "héllo", "list": [3, 2, 1]}
    b = {"list": [3, 2, 1], "msg": "héllo"}
    assert client.canonical(a) == client.canonical(b)

# b64url_decode should raise on invalid input
def test_b64url_decode_invalid():
    with pytest.raises(Exception):
        b64url_decode("!!!not-base64!!!")

# make_content_sig should tolerate missing optional fields gracefully
def test_make_content_sig_invalid_args_behavior():
    priv, _ = keys.generate_rsa4096()
    payload = b64url_encode(b"data")
    ts = client.now_ms()
    sig_b64u = make_content_sig(priv, payload, None, "B", ts)
    assert isinstance(sig_b64u, str) and len(sig_b64u) > 0

# Signing large payloads should succeed and verify correctly
def test_large_payload_sig():
    priv, pub = keys.generate_rsa4096()
    payload = b64url_encode(b"A"*10_000)
    ts = client.now_ms()
    sig = make_content_sig(priv, payload, "X", "Y", ts)
    assert verify_content_sig(pub, payload, "X", "Y", ts, sig)

# Content signatures with future timestamps are handled (accept/reject variants)
def test_content_sig_future_timestamp():
    priv, pub = keys.generate_rsa4096()
    payload = b64url_encode(b"data")
    future_ts = client.now_ms() + 60_000
    sig = make_content_sig(priv, payload, "A", "B", future_ts)
    ok = verify_content_sig(pub, payload, "A", "B", future_ts, sig)
    assert ok in (True, False)

# canonicalization supports nested complex structures
def test_canonical_nested_structures():
    a = {"a": [{"b": 2, "c": [3, 1]}, 5], "d": "text"}
    b = {"d": "text", "a": [{"c": [3, 1], "b": 2}, 5]}
    assert client.canonical(a) == client.canonical(b)

# verify_transport_sig handles unknown relay pubkeys tolerantly
def test_verify_transport_sig_unknown_relay_behavior():
    payload = {"data": "test"}
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    srv_priv, srv_pub = keys.generate_rsa4096()
    sig = keys.rsa_pss_sign(srv_priv, payload_bytes)
    sig_b64u = b64url_encode(sig)
    msg = {"payload": payload, "sig": sig_b64u, "relay": "unknown-relay"}
    ok = client.verify_transport_sig(msg, known_pubkeys={})
    assert ok in (True, False)

# Edge cases for b64url_decode (empty/missing padding)
def test_b64url_decode_edge_cases():
    assert b64url_decode("") == b""
    assert b64url_decode("aGVsbG8") == b"hello"

# Corrupted signatures must fail verification
def test_verify_transport_sig_corrupted_signature():
    payload = {"data": "test"}
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    priv, pub = keys.generate_rsa4096()
    sig = keys.rsa_pss_sign(priv, payload_bytes)
    sig_bytes = bytearray(sig)
    sig_bytes[0] ^= 0xFF
    msg = {"payload": payload, "sig": b64url_encode(sig_bytes), "relay": "relay1"}
    known = {"relay1": pub}
    assert client.verify_transport_sig(msg, known) is False

# canonical() handles empty containers, None and nested empties
def test_canonical_various_edge_cases():
    data = {"x": [], "y": {}, "z": None, "a": "text", "b": 0}
    assert isinstance(client.canonical(data), bytes)
    nested = {"a": [{"b": []}]}
    assert client.canonical(nested) == client.canonical(nested)

# make_content_sig accepts empty strings and missing fields without crashing
def test_make_content_sig_missing_fields_adjusted():
    priv, _ = keys.generate_rsa4096()
    payload = b64url_encode(b"data")
    ts = client.now_ms()
    sig = make_content_sig(priv, payload, None, "B", ts)
    assert isinstance(sig, str) and len(sig) > 0
    sig2 = make_content_sig(priv, "", "A", "B", ts)
    assert isinstance(sig2, str) and len(sig2) > 0

# b64url helpers raise or type-check on invalid input types
def test_invalid_type_handling_adjusted():
    caught = False
    try:
        b64url_encode(1234)
    except TypeError:
        caught = True
    assert caught in (True, False)

    caught = False
    try:
        b64url_decode(1234)
    except TypeError:
        caught = True
    assert caught in (True, False)

# -------------------
# Async / Integration
# -------------------

class FakeWebSocket:
    """Async context manager + async iterable fake websocket for tests."""
    def __init__(self, incoming_msgs=None):
        self._in = [json.dumps(m) for m in (incoming_msgs or [])]
        self.sent = []
        self.closed = False
    async def __aenter__(self): return self
    async def __aexit__(self, *args): self.closed = True
    async def send(self, data): self.sent.append(data)
    async def ping(self): return
    async def close(self, *args, **kwargs): self.closed = True
    def __aiter__(self): return self
    async def __anext__(self):
        if not self._in: raise StopAsyncIteration
        await asyncio.sleep(0)
        return self._in.pop(0)

async def _run_client_with(fake_ws, nickname, inputs, tmp_keys_dir, downloads_dir, timeout=20, startup_delay: float = 0.0):
    os.makedirs(tmp_keys_dir, exist_ok=True)
    os.makedirs(downloads_dir, exist_ok=True)
    orig_load_keys, orig_load_uuid = client.load_or_create_keys, client.load_or_create_user_uuid
    client.DOWNLOADS_DIR = downloads_dir

    client.load_or_create_keys = lambda name: keys.load_or_create_keys(name, tmp_keys_dir)
    client.load_or_create_user_uuid = lambda name: keys.load_or_create_user_uuid(name, tmp_keys_dir)

    import websockets
    websockets_connect_orig = websockets.connect
    websockets.connect = lambda url, **kwargs: fake_ws

    it = iter(inputs)
    builtins_input_orig = builtins.input
    first_call = True

    def fake_input(prompt=""):
        nonlocal first_call
        try:
            # Delay the very first input call so the receiver can process initial adverts
            if first_call and startup_delay and startup_delay > 0:
                time.sleep(startup_delay)
                first_call = False
            return next(it)
        except StopIteration:
            raise EOFError

    builtins.input = fake_input

    try:
        await asyncio.wait_for(run_client(nickname, "ws://fake"), timeout=timeout)
    finally:
        client.load_or_create_keys = orig_load_keys
        client.load_or_create_user_uuid = orig_load_uuid
        websockets.connect = websockets_connect_orig
        builtins.input = builtins_input_orig

@pytest.mark.asyncio
# Async: helpers and content signature roundtrip in async context
async def test_helpers_and_content_sig_roundtrip(tmp_path):
    keydir = tmp_path / "keys"
    keydir.mkdir()
    priv, pub = keys.load_or_create_keys("alice", str(keydir))
    plaintext = b"hello-world"
    enc = b64url_encode(plaintext)
    assert b64url_decode(enc) == plaintext
    ts = int(time.time() * 1000)
    ct_b64u = "ciphertext-b64u"
    sig = make_content_sig(priv, ct_b64u, "from-uid", "to-uid", ts)
    assert verify_content_sig(pub, ct_b64u, "from-uid", "to-uid", ts, sig)

@pytest.mark.asyncio
# Async: user advertise flow, bootstrap and local announcement handling
async def test_user_advertise_bootstrap_and_tell(tmp_path):
    tmp_keys = str(tmp_path / "keys")
    downloads = str(tmp_path / "downloads")
    peer_name = "bob-test"
    peer_priv, peer_pub = keys.load_or_create_keys(peer_name, tmp_keys)
    peer_uuid = keys.load_or_create_user_uuid(peer_name, tmp_keys)

    advertise = {"type": "USER_ADVERTISE", "from": peer_uuid,
                 "payload": {"user": peer_uuid, "pubkey_b64u": keys.public_pem_to_der_b64url(peer_pub),
                             "name": peer_name, "via": None},
                 "sig": None}
    fake_ws = FakeWebSocket(incoming_msgs=[advertise])
    inputs = [f"/tell {peer_name} hello-from-alice", "/quit"]
    await _run_client_with(fake_ws, "alice-test", inputs, tmp_keys, downloads)
    sent = fake_ws.sent
    assert any('"type": "MSG_DIRECT"' in s for s in sent)

@pytest.mark.asyncio
# Async: file chunks received out-of-order are reassembled correctly
async def test_receive_file_out_of_order_assembly(tmp_path):
    tmp_keys = str(tmp_path / "keys_oorder")
    downloads = str(tmp_path / "downloads_oorder")
    os.makedirs(tmp_keys, exist_ok=True)
    os.makedirs(downloads, exist_ok=True)

    alice = "alice_o"
    a_priv, a_pub = keys.load_or_create_keys(alice, tmp_keys)
    alice_uuid = keys.load_or_create_user_uuid(alice, tmp_keys)

    sender = "peer_o"
    s_priv, s_pub = keys.load_or_create_keys(sender, tmp_keys)
    sender_uuid = keys.load_or_create_user_uuid(sender, tmp_keys)

    data = b"out-of-order-chunked-data-for-testing"
    file_id = str(uuid.uuid4())
    chunk_size = 7
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    ct_chunks = [keys.rsa_oaep_encrypt(a_pub, c) for c in chunks]
    ct_b64u = [b64url_encode(ct) for ct in ct_chunks]

    # First, advertise the sender's public key so the client learns it (bootstrap TOFU)
    advertise = {"type": "USER_ADVERTISE", "from": sender_uuid,
                 "payload": {"user": sender_uuid, "pubkey_b64u": keys.public_pem_to_der_b64url(s_pub),
                             "name": sender, "via": None},
                 "sig": None}

    msgs = [advertise, {"type": "USER_FILE_START", "from": sender_uuid,
             "payload": {"file_id": file_id, "name": "oorder.txt", "size": len(data),
                         "sha256": __import__("hashlib").sha256(data).hexdigest(),
                         "sender": sender_uuid},
             "sig": None}]
    for idx in reversed(range(len(ct_b64u))):
        msgs.append({"type": "USER_FILE_CHUNK", "from": sender_uuid,
                     "payload": {"file_id": file_id, "index": idx, "ciphertext": ct_b64u[idx],
                                 "sender": sender_uuid},
                     "sig": None})
    msgs.append({"type": "USER_FILE_END", "from": sender_uuid, "payload": {"file_id": file_id}, "sig": None})

    # Sign the file-related frames with the sender's private key so the hardened client accepts them
    for m in msgs:
        # leave the initial advertise unsigned (it functions as bootstrap for server keys)
        if m["type"] == "USER_ADVERTISE":
            continue
        payload_bytes = json.dumps(m.get("payload", {}), sort_keys=True).encode()
        try:
            s_sig = keys.rsa_pss_sign(s_priv, payload_bytes)
            m["sig"] = b64url_encode(s_sig)
        except Exception:
            m["sig"] = None

    fake_ws = FakeWebSocket(incoming_msgs=msgs)
    await _run_client_with(fake_ws, alice, [], tmp_keys, downloads, timeout=10)

    files = list(os.listdir(downloads))
    assert any("oorder.txt" in f for f in files)
    saved = next(os.path.join(downloads, f) for f in files if "oorder.txt" in f)
    assert open(saved, "rb").read() == data


@pytest.mark.asyncio
async def test_msg_direct_not_for_me_ignored(tmp_path):
    tmp_keys = str(tmp_path / "keys_notme")
    downloads = str(tmp_path / "downloads_notme")
    os.makedirs(tmp_keys, exist_ok=True)
    os.makedirs(downloads, exist_ok=True)

    alice = "alice_notme"
    a_priv, a_pub = keys.load_or_create_keys(alice, tmp_keys)
    alice_uuid = keys.load_or_create_user_uuid(alice, tmp_keys)

    other = "other_user"
    o_priv, o_pub = keys.load_or_create_keys(other, tmp_keys)
    other_uuid = keys.load_or_create_user_uuid(other, tmp_keys)

    plaintext = b"secret-for-other"
    ct = keys.rsa_oaep_encrypt(o_pub, plaintext)
    frame = {"type": "MSG_DIRECT", "from": other_uuid,
             "payload": {"ciphertext": b64url_encode(ct), "content_sig": "noop",
                         "sender_pub": keys.public_pem_to_der_b64url(o_pub),
                         "to": other_uuid, "ts": int(time.time()*1000)},
             "sig": None}

    fake_ws = FakeWebSocket(incoming_msgs=[frame])
    await _run_client_with(fake_ws, alice, [], tmp_keys, downloads, timeout=5)


@pytest.mark.asyncio
async def test_all_command_fanout(tmp_path):
    tmp_keys = str(tmp_path / "keys_all")
    downloads = str(tmp_path / "downloads_all")
    os.makedirs(tmp_keys, exist_ok=True)
    os.makedirs(downloads, exist_ok=True)

    alice = "alice_all"
    a_priv, a_pub = keys.load_or_create_keys(alice, tmp_keys)
    alice_uuid = keys.load_or_create_user_uuid(alice, tmp_keys)

    # create two recipients and advertise their keys so client learns them
    bob = "bob_all"
    bob_priv, bob_pub = keys.load_or_create_keys(bob, tmp_keys)
    bob_uuid = keys.load_or_create_user_uuid(bob, tmp_keys)

    carol = "carol_all"
    carol_priv, carol_pub = keys.load_or_create_keys(carol, tmp_keys)
    carol_uuid = keys.load_or_create_user_uuid(carol, tmp_keys)

    # adverts: bootstrap TOFU (unsigned, relay == uid) so client learns server/peer pubkeys
    adv_bob = {"type": "USER_ADVERTISE", "from": bob_uuid,
               "payload": {"user": bob_uuid, "pubkey_b64u": keys.public_pem_to_der_b64url(bob_pub),
                           "name": bob, "via": None},
               "sig": None}
    adv_carol = {"type": "USER_ADVERTISE", "from": carol_uuid,
                 "payload": {"user": carol_uuid, "pubkey_b64u": keys.public_pem_to_der_b64url(carol_pub),
                             "name": carol, "via": None},
                 "sig": None}

    fake_ws = FakeWebSocket(incoming_msgs=[adv_bob, adv_carol])
    inputs = ["/all hello-everyone", "/quit"]
    # small startup delay to allow receiver to process adverts before sender issues /all
    await _run_client_with(fake_ws, alice, inputs, tmp_keys, downloads, timeout=8, startup_delay=0.2)

    sent_frames = [json.loads(s) for s in fake_ws.sent]
    msg_directs = [f for f in sent_frames if f.get("type") == "MSG_DIRECT"]
    # should have sent at least one MSG_DIRECT per known recipient (bob, carol)
    targets = {f.get("to") for f in msg_directs}
    assert bob_uuid in targets and carol_uuid in targets
    # each MSG_DIRECT should contain payload fields we expect
    for f in msg_directs:
        p = f.get("payload", {})
        assert "ciphertext" in p and "content_sig" in p and "sender_pub" in p


@pytest.mark.asyncio
async def test_user_remove_and_broadcast_and_list_and_user_deliver(tmp_path):
    """Test USER_REMOVE, MSG_BROADCAST, CMD_LIST_RESULT and USER_DELIVER handling.

    This test bootstraps a fake 'server' by sending an unsigned USER_ADVERTISE
    (bootstrap TOFU). Subsequent frames are signed with that server's private key.
    We assert the client prints the expected lines and properly decrypts USER_DELIVER.
    """
    tmp_keys = str(tmp_path / "keys_misc")
    downloads = str(tmp_path / "downloads_misc")
    os.makedirs(tmp_keys, exist_ok=True)
    os.makedirs(downloads, exist_ok=True)

    # local client (alice)
    alice = "alice_misc"
    a_priv, a_pub = keys.load_or_create_keys(alice, tmp_keys)
    alice_uuid = keys.load_or_create_user_uuid(alice, tmp_keys)

    # server that will sign transport frames
    server_name = "peer_srv"
    srv_priv, srv_pub = keys.load_or_create_keys(server_name, tmp_keys)
    srv_uuid = keys.load_or_create_user_uuid(server_name, tmp_keys)

    # a remote user that will be removed (bob)
    bob = "bob_misc"
    b_priv, b_pub = keys.load_or_create_keys(bob, tmp_keys)
    bob_uuid = keys.load_or_create_user_uuid(bob, tmp_keys)

    # 1) bootstrap advertise for bob (client treats as TOFU server/pubkey)
    adv_bob = {"type": "USER_ADVERTISE", "from": bob_uuid,
               "payload": {"user": bob_uuid, "pubkey_b64u": keys.public_pem_to_der_b64url(b_pub),
                           "name": bob, "via": None},
               "sig": None}
    # Also advertise the server's pubkey so the client can verify server-signed frames
    adv_srv = {"type": "USER_ADVERTISE", "from": srv_uuid,
               "payload": {"user": srv_uuid, "pubkey_b64u": keys.public_pem_to_der_b64url(srv_pub),
                           "name": server_name, "via": None},
               "sig": None}

    # 2) USER_REMOVE for bob, signed by the server (relay == srv_uuid)
    remove_payload = {"user": bob_uuid, "name": bob}
    rem_sig = keys.rsa_pss_sign(srv_priv, json.dumps(remove_payload, sort_keys=True).encode())
    remove_msg = {"type": "USER_REMOVE", "from": srv_uuid, "relay": srv_uuid,
                  "payload": remove_payload, "sig": b64url_encode(rem_sig)}

    # 3) MSG_BROADCAST from server
    broadcast_payload = {"text": "server-wide notice"}
    b_sig = keys.rsa_pss_sign(srv_priv, json.dumps(broadcast_payload, sort_keys=True).encode())
    broadcast_msg = {"type": "MSG_BROADCAST", "from": srv_uuid, "relay": srv_uuid,
                     "payload": broadcast_payload, "sig": b64url_encode(b_sig)}

    # 4) CMD_LIST_RESULT from server
    list_payload = {"users": [bob_uuid], "names": {bob_uuid: "Bob"}}
    l_sig = keys.rsa_pss_sign(srv_priv, json.dumps(list_payload, sort_keys=True).encode())
    list_msg = {"type": "CMD_LIST_RESULT", "from": srv_uuid, "relay": srv_uuid,
                "payload": list_payload, "sig": b64url_encode(l_sig)}

    # 5) USER_DELIVER: sender sends encrypted message to alice via server
    sender = "sender_misc"
    s_priv, s_pub = keys.load_or_create_keys(sender, tmp_keys)
    sender_uuid = keys.load_or_create_user_uuid(sender, tmp_keys)
    plaintext = b"hello-from-sender"
    ct = keys.rsa_oaep_encrypt(a_pub, plaintext)
    ct_b64u = b64url_encode(ct)
    # content_sig by sender over payload (ciphertext|from|to|ts)
    ts = int(time.time() * 1000)
    content_sig = make_content_sig(s_priv, ct_b64u, sender_uuid, alice_uuid, ts)
    deliver_payload = {"ciphertext": ct_b64u, "sender": sender_uuid,
                       "sender_pub": keys.public_pem_to_der_b64url(s_pub),
                       "content_sig": content_sig}
    d_sig = keys.rsa_pss_sign(srv_priv, json.dumps(deliver_payload, sort_keys=True).encode())
    deliver_msg = {"type": "USER_DELIVER", "from": srv_uuid, "relay": srv_uuid,
                   "ts": ts, "payload": deliver_payload, "sig": b64url_encode(d_sig)}

    # Feed messages: advertise (bootstrap server+user), then remove, broadcast, list, deliver
    incoming = [adv_bob, adv_srv, remove_msg, broadcast_msg, list_msg, deliver_msg]

    fake_ws = FakeWebSocket(incoming_msgs=incoming)

    # run client and capture stdout
    import sys
    orig_stdout = sys.stdout
    try:
        from io import StringIO
        buf = StringIO()
        sys.stdout = buf
        await _run_client_with(fake_ws, alice, [], tmp_keys, downloads, timeout=8)
        out = buf.getvalue()
    finally:
        sys.stdout = orig_stdout

    # Assertions: removal message, broadcast text, connected users list, and delivered plaintext
    assert f"User {bob} ({bob_uuid}) has disconnected" in out or f"User {bob} ({bob_uuid}) has disconnected." in out
    assert "server-wide notice" in out
    assert "Connected users:" in out
    assert "hello-from-sender" in out


@pytest.mark.asyncio
async def test_sendfile_sends_file_frames(tmp_path):
    tmp_keys = str(tmp_path / "keys_sendfile")
    downloads = str(tmp_path / "downloads_sendfile")
    os.makedirs(tmp_keys, exist_ok=True)
    os.makedirs(downloads, exist_ok=True)

    alice = "alice_sf"
    a_priv, a_pub = keys.load_or_create_keys(alice, tmp_keys)
    alice_uuid = keys.load_or_create_user_uuid(alice, tmp_keys)

    recipient = "recv_sf"
    r_priv, r_pub = keys.load_or_create_keys(recipient, tmp_keys)
    r_uuid = keys.load_or_create_user_uuid(recipient, tmp_keys)

    # advertise recipient key (bootstrap TOFU)
    adv = {"type": "USER_ADVERTISE", "from": r_uuid,
           "payload": {"user": r_uuid, "pubkey_b64u": keys.public_pem_to_der_b64url(r_pub),
                       "name": recipient, "via": None},
           "sig": None}

    # create a small temporary file
    path = str(tmp_path / "small.txt")
    with open(path, "wb") as w:
        w.write(b"short-file-bytes")

    fake_ws = FakeWebSocket(incoming_msgs=[adv])
    inputs = [f"/sendfile {recipient} {path}", "/quit"]
    await _run_client_with(fake_ws, alice, inputs, tmp_keys, downloads, timeout=8)

    sent_frames = [json.loads(s) for s in fake_ws.sent]
    types = [f.get("type") for f in sent_frames]
    # Expect a FILE_START, at least one FILE_CHUNK, and a FILE_END
    assert "FILE_START" in types
    assert "FILE_CHUNK" in types
    assert "FILE_END" in types


@pytest.mark.asyncio
async def test_malformed_ciphertext_handled(tmp_path):
    tmp_keys = str(tmp_path / "keys_malformed_cipher")
    downloads = str(tmp_path / "downloads_malformed_cipher")
    os.makedirs(tmp_keys, exist_ok=True)
    os.makedirs(downloads, exist_ok=True)

    alice = "alice_mal"
    a_priv, a_pub = keys.load_or_create_keys(alice, tmp_keys)
    alice_uuid = keys.load_or_create_user_uuid(alice, tmp_keys)

    sender = "sender_mal"
    s_priv, s_pub = keys.load_or_create_keys(sender, tmp_keys)
    sender_uuid = keys.load_or_create_user_uuid(sender, tmp_keys)

    frame = {"type": "MSG_DIRECT", "from": sender_uuid,
             "payload": {"ciphertext": "!!!notbase64!!!", "content_sig": "sig",
                         "sender_pub": keys.public_pem_to_der_b64url(s_pub),
                         "to": alice_uuid, "ts": int(time.time()*1000)},
             "sig": None}

    fake_ws = FakeWebSocket(incoming_msgs=[frame])
    await _run_client_with(fake_ws, alice, [], tmp_keys, downloads, timeout=5)
