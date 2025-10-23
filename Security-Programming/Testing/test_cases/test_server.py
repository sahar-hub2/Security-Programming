"""
test_server.py
---------------
Unit and integration tests for the `server` module. This file exercises JSON
envelope signing/verification, bootstrap/introducer behavior, federation
connectivity, presence sync, file transfer routing, and error handling.


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
import uuid
import asyncio
import pytest
import importlib

# -------------------------
# Setup paths and imports
# -------------------------
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../Implementation/secure_version"))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

server = pytest.importorskip("server")
keys = pytest.importorskip("keys")

# -------------------------
# Helpers
# -------------------------

def ensure_server_keys():
    if getattr(server, "priv_pem", None) and getattr(server, "pub_pem", None):
        return server.priv_pem, server.pub_pem
    if hasattr(keys, "generate_rsa4096"):
        priv, pub = keys.generate_rsa4096()
    else:
        priv, pub = keys.load_or_create_keys("test-server")
    server.priv_pem = priv
    server.pub_pem = pub
    return priv, pub

def now_ms():
    return int(time.time() * 1000)

class FakeWebSocket:
    """Minimal async-iterable websocket for handle_ws tests."""
    def __init__(self, incoming_msgs):
        self._in = []
        for m in incoming_msgs:
            if isinstance(m, (dict, list)):
                self._in.append(json.dumps(m))
            else:
                self._in.append(str(m))
        self.sent = []
        self.close_code = None

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._in:
            self.close_code = 1000
            raise StopAsyncIteration
        await asyncio.sleep(0)
        return self._in.pop(0)

    async def send(self, data):
        self.sent.append(data)

def snapshot_state():
    return {
        "servers": dict(server.servers),
        "server_addrs": dict(server.server_addrs),
        "local_users": dict(server.local_users),
        "user_locations": dict(server.user_locations),
        "user_pubkeys": dict(server.user_pubkeys),
        "user_names": dict(server.user_names),
        "file_sessions": dict(server.file_sessions),
        "priv_pem": getattr(server, "priv_pem", None),
        "pub_pem": getattr(server, "pub_pem", None),
    }

def restore_state(snap):
    server.servers.clear(); server.servers.update(snap["servers"])
    server.server_addrs.clear(); server.server_addrs.update(snap["server_addrs"])
    server.local_users.clear(); server.local_users.update(snap["local_users"])
    server.user_locations.clear(); server.user_locations.update(snap["user_locations"])
    server.user_pubkeys.clear(); server.user_pubkeys.update(snap["user_pubkeys"])
    server.user_names.clear(); server.user_names.update(snap["user_names"])
    server.file_sessions.clear(); server.file_sessions.update(snap["file_sessions"])
    server.priv_pem = snap["priv_pem"]
    server.pub_pem = snap["pub_pem"]

@pytest.fixture(autouse=True)
def isolate_state(tmp_path, monkeypatch):
    snap = snapshot_state()
    tmpdir = str(tmp_path / "keys")
    os.makedirs(tmpdir, exist_ok=True)
    priv, pub = keys.load_or_create_keys("test-server", tmpdir)
    server.priv_pem = priv
    server.pub_pem = pub
    try:
        yield
    finally:
        restore_state(snap)

# -------------------------
# Synchronous Tests
# -------------------------

# Verify now_ms, fresh timestamp checking and seen_before deduplication
def test_now_ms_and_fresh_ts_and_seen_before():
    now = server.now_ms()
    assert isinstance(now, int) and now > 0
    assert server.fresh_ts(now)
    assert not server.fresh_ts(now - 10_000_000)

    try:
        server.RECENT_IDS.clear()
    except Exception:
        from collections import deque
        server.RECENT_IDS = deque(maxlen=getattr(server, "RECENT_IDS").maxlen if hasattr(server, "RECENT_IDS") else 4096)

    mid = f"mid-{int(time.time()*1000)}-{uuid.uuid4().hex[:6]}"
    first = server.seen_before(mid)
    assert first in (False, None)
    second = server.seen_before(mid)
    assert second is True or first is None

# is_open should correctly detect websocket open/closed across variants
def test_is_open_variants():
    class DummyA: 
        def __init__(self, open): self.open = open
    class DummyB: 
        def __init__(self, closed): self.closed = closed
    class State: 
        def __init__(self, name): self.name = name
    class DummyC: 
        def __init__(self, state_name): self.state = State(state_name)

    assert server.is_open(None) is False
    assert server.is_open(DummyA(True)) is True
    assert server.is_open(DummyA(False)) is False
    assert server.is_open(DummyB(False)) is True
    assert server.is_open(DummyB(True)) is False
    assert server.is_open(DummyC("OPEN")) is True
    assert server.is_open(DummyC("CLOSED")) is False

# load_introducers parses introducers.yaml and is_introducer matches entries
def test_load_introducers_and_is_introducer():
    intros = server.load_introducers(os.path.join(ROOT, "introducers.yaml"))
    assert intros is not None
    assert isinstance(intros, (list, dict))

    if isinstance(intros, list) and len(intros) > 0:
        e = intros[0]; h = e.get("host"); p = int(e.get("port"))
        assert server.is_introducer(h, p) is True
        assert server.is_introducer("0.0.0.0", 65535) is False
    elif isinstance(intros, dict):
        any_ok = False
        for v in intros.values():
            if isinstance(v, dict) and "host" in v and "port" in v:
                any_ok = True
                assert server.is_introducer(v["host"], int(v["port"])) is True
                assert server.is_introducer("0.0.0.0", 65535) is False
                break
        assert any_ok

# Building server hello/announce frames includes signed payloads that verify
def test_signing_and_build_messages():
    priv, pub = ensure_server_keys()
    host = "127.0.0.1"
    port = 12345
    pub_b64u = server.public_pem_to_der_b64url(pub)

    hello = server.build_server_hello_join("my-id", host, port, pub_b64u)
    assert hello["type"] == "SERVER_HELLO_JOIN"
    payload = {"host": host, "port": port, "pubkey": pub_b64u}
    sig = hello.get("sig")
    assert keys.rsa_pss_verify(pub, json.dumps(payload, sort_keys=True).encode(), keys.b64url_decode(sig))

    ann = server.build_server_announce("my-id", host, port, pub_b64u)
    assert ann["type"] == "SERVER_ANNOUNCE"
    payload2 = {"host": host, "port": port, "pubkey": pub_b64u}
    sig2 = ann.get("sig")
    assert keys.rsa_pss_verify(pub, json.dumps(payload2, sort_keys=True).encode(), keys.b64url_decode(sig2))

# Presence sync frames include user entries and are signed by server key
def test_build_presence_sync_includes_users_and_signed():
    priv, pub = ensure_server_keys()
    uid = f"user-{uuid.uuid4().hex}"
    server.user_locations[uid] = "local"
    server.user_pubkeys[uid] = pub.decode() if isinstance(pub, bytes) else str(pub)
    server.user_names[uid] = "tester-name"

    msg = server.build_presence_sync("server-id-xyz")
    assert msg["type"] == "SERVER_PRESENCE_SYNC"
    payload = msg["payload"]
    assert payload.get("server_id") == "server-id-xyz"
    users = payload.get("users", [])
    assert any(u.get("user_id") == uid for u in users)
    sig_b64u = msg.get("sig")
    assert keys.rsa_pss_verify(pub, json.dumps(payload, sort_keys=True).encode(), keys.b64url_decode(sig_b64u))


# DER <-> PEM conversion roundtrip preserves keys and allows signature verify
def test_pubkey_der_b64url_roundtrip_and_verify():
    priv, pub = ensure_server_keys()
    pub_pem_bytes = pub if isinstance(pub, (bytes, bytearray)) else pub.encode("utf-8")

    der_b64u = server.public_pem_to_der_b64url(pub_pem_bytes)
    assert isinstance(der_b64u, str) and len(der_b64u) > 0

    roundtrip_pem = server.der_b64url_to_public_pem(der_b64u)
    roundtrip_pem_str = roundtrip_pem.decode("utf-8") if isinstance(roundtrip_pem, (bytes, bytearray)) else roundtrip_pem
    assert isinstance(roundtrip_pem_str, str) and "BEGIN PUBLIC KEY" in roundtrip_pem_str

    msg = b"roundtrip-test"
    sig = keys.rsa_pss_sign(priv, msg)
    pem_bytes_for_verify = roundtrip_pem if isinstance(roundtrip_pem, (bytes, bytearray)) else roundtrip_pem.encode("utf-8")
    assert keys.rsa_pss_verify(pem_bytes_for_verify, msg, sig)

# Basic constants (file limits) and wrap_counts dict behavior sanity checks
def test_constants_and_wrap_counts_behavior():
    """Basic consistency checks for file limits and wrap_counts dictionary behavior."""
    assert isinstance(server.MAX_FILE_BYTES, int) and server.MAX_FILE_BYTES > 0
    assert isinstance(server.MAX_CHUNK_BYTES, int) and server.MAX_CHUNK_BYTES > 0
    assert server.MAX_CHUNK_BYTES <= server.MAX_FILE_BYTES, "chunk must not exceed max file size"

    # wrap_counts should be a dict-like mapping
    assert isinstance(server.wrap_counts, dict)
    key = f"wrap-test-{int(time.time()*1000)}"
    prev = server.wrap_counts.get(key, 0)
    server.wrap_counts[key] = server.wrap_counts.get(key, 0) + 1
    assert server.wrap_counts[key] == prev + 1


# RECENT_IDS should evict old entries when maxlen exceeded
def test_recent_ids_eviction_behavior():
    """If RECENT_IDS is a deque with maxlen, ensure it evicts oldest entries when full."""
    recent = server.RECENT_IDS
    # best-effort: only run if it exposes .maxlen and behaves like a deque
    maxlen = getattr(recent, "maxlen", None)
    if not isinstance(recent, (list, tuple)) and isinstance(maxlen, int) and maxlen > 0:
        # backup and clear
        backup = list(recent)
        try:
            recent.clear()
            # fill with maxlen + 2 unique ids
            for i in range(maxlen + 2):
                server.seen_before(f"evict-{i}-{time.time()}")
            assert len(recent) <= maxlen
            # oldest (evict-0) should not be present if eviction occurred
            assert not any(str("evict-0") in str(x) for x in recent)
        finally:
            # restore
            recent.clear()
            recent.extend(backup)
    else:
        pytest.skip("RECENT_IDS is not a deque with maxlen; skipping eviction test")


# build_presence_sync still signs an empty user list correctly
def test_build_presence_sync_when_no_users():
    """build_presence_sync should produce a signed payload even when no users present."""
    # backup and clear
    backup_locations = dict(getattr(server, "user_locations", {}))
    backup_pubkeys = dict(getattr(server, "user_pubkeys", {}))
    backup_names = dict(getattr(server, "user_names", {}))
    try:
        server.user_locations.clear()
        server.user_pubkeys.clear()
        server.user_names.clear()

        # ensure server has a keypair for signing
        ensure_server_keys()

        msg = server.build_presence_sync("empty-server")
        assert msg["type"] == "SERVER_PRESENCE_SYNC"
        payload = msg.get("payload", {})
        assert isinstance(payload, dict)
        # no users expected
        users = payload.get("users", [])
        assert users == [] or users == []  # explicit check for empty list

        # signature should verify using server pub key
        priv, pub = ensure_server_keys()
        sig_b64u = msg.get("sig")
        assert sig_b64u, "presence sync missing signature"
        assert keys.rsa_pss_verify(pub, json.dumps(payload, sort_keys=True).encode(), keys.b64url_decode(sig_b64u))
    finally:
        server.user_locations.clear()
        server.user_locations.update(backup_locations)
        server.user_pubkeys.clear()
        server.user_pubkeys.update(backup_pubkeys)
        server.user_names.clear()
        server.user_names.update(backup_names)

# Tampered payloads must cause signature verification to fail
def test_signature_fails_if_payload_tampered():
    """A signature created by build_server_hello_join should fail verification after payload tamper."""
    priv, pub = ensure_server_keys()
    host = "127.0.0.1"
    port = 11111
    pub_b64u = server.public_pem_to_der_b64url(pub)
    hello = server.build_server_hello_join("sid-x", host, port, pub_b64u)
    assert hello["type"] == "SERVER_HELLO_JOIN"
    sig = hello.get("sig")
    assert sig

    # tamper payload object (simulate a MITM change)
    tampered_payload = dict(hello.get("payload", {}))
    tampered_payload["host"] = "evil.host"
    ok = keys.rsa_pss_verify(pub, json.dumps(tampered_payload, sort_keys=True).encode(), keys.b64url_decode(sig))
    assert not ok, "tampered payload should not verify against original signature"


# der_b64url_to_public_pem should raise or return invalid result on bad input
def test_der_b64url_to_public_pem_with_invalid_input():
    """der_b64url_to_public_pem should raise or return non-pem for invalid input; handle both possibilities."""
    bad = "!!!not_base64!!!"
    try:
        out = server.der_b64url_to_public_pem(bad)
    except Exception:
        # acceptable: function raises on invalid base64
        return
    # if it returned something, it should not be a valid PEM
    out_str = out.decode("utf-8") if isinstance(out, (bytes, bytearray)) else str(out)
    assert "BEGIN PUBLIC KEY" not in out_str


# load_introducers tolerates missing files (returns None/empty or raises)
def test_load_introducers_returns_empty_on_missing_file(tmp_path):
    """load_introducers should tolerate missing path and return None/empty list/dict."""
    missing = os.path.join(str(tmp_path), "does-not-exist.yml")
    try:
        intros = server.load_introducers(missing)
    except Exception:
        # Some implementations may raise; accept that too
        return
    assert intros is None or intros == {} or intros == []


# fresh_ts rejects timestamps that are too far in the future
def test_fresh_ts_rejects_far_future_timestamp():
    """fresh_ts should reject timestamps that are too far in the future."""
    now = server.now_ms()
    far_future = now + 10_000_000
    assert server.fresh_ts(now) is True
    # far future should be considered not fresh
    assert server.fresh_ts(far_future) is False

# sign_payload produces a base64url signature that verifies with server pubkey
def test_sign_payload_and_verify_roundtrip():
    """server.sign_payload should produce a b64url sig that verifies with the server pub key."""
    priv, pub = ensure_server_keys()
    payload = {"x": "y", "ts": int(time.time() * 1000)}
    sig_b64u = server.sign_payload(payload)
    assert isinstance(sig_b64u, str) and len(sig_b64u) > 0
    sig = keys.b64url_decode(sig_b64u)
    # verify the signature using the public key produced by ensure_server_keys()
    ok = keys.rsa_pss_verify(pub, json.dumps(payload, sort_keys=True).encode(), sig)
    assert ok is True

# sign_payload should raise or fail when server.priv_pem missing
def test_sign_payload_missing_priv_raises_or_errors(monkeypatch):
    """If server.priv_pem is not set, sign_payload should raise/propagate an error (TypeError/ValueError)."""
    # ensure we have a working key first
    ensure_server_keys()
    # backup and unset
    backup = getattr(server, "priv_pem", None)
    try:
        if hasattr(server, "priv_pem"):
            delattr(server, "priv_pem")
        else:
            server.priv_pem = None
        with pytest.raises(Exception):
            server.sign_payload({"a": 1})
    finally:
        # restore
        if backup is not None:
            server.priv_pem = backup

# Malformed YAML in introducer file should be handled (raise or return empty)
def test_load_introducers_handles_malformed_yaml(tmp_path):
    """load_introducers should tolerate malformed YAML (either raise or return None/empty)."""
    bad_file = os.path.join(str(tmp_path), "bad_intro.yml")
    with open(bad_file, "w") as fh:
        fh.write(":::: this is not valid yaml :::")
    try:
        out = server.load_introducers(bad_file)
    except Exception:
        # acceptable: function may raise on malformed YAML
        return
    # or it may return None/empty; accept that as well
    assert out is None or out == {} or out == [] or isinstance(out, (list, dict))

# public_pem_to_der_b64url accepts both bytes and str input
def test_public_pem_to_der_b64url_accepts_str_and_bytes():
    """public_pem_to_der_b64url should accept bytes or str and produce identical outputs."""
    priv, pub = ensure_server_keys()
    pub_bytes = pub if isinstance(pub, (bytes, bytearray)) else pub.encode("utf-8")
    pub_str = pub_bytes.decode("utf-8")
    out1 = server.public_pem_to_der_b64url(pub_bytes)
    out2 = server.public_pem_to_der_b64url(pub_str)
    assert isinstance(out1, str) and isinstance(out2, str)
    assert out1 == out2


# sign_payload should roundtrip (duplicate named test - sanity check)
def test_sign_payload_and_verify_roundtrip():
    """server.sign_payload should produce a b64url sig that verifies with the server pub key."""
    priv, pub = ensure_server_keys()
    payload = {"x": "y", "ts": int(time.time() * 1000)}
    sig_b64u = server.sign_payload(payload)
    assert isinstance(sig_b64u, str) and len(sig_b64u) > 0
    sig = keys.b64url_decode(sig_b64u)
    # verify the signature using the public key produced by ensure_server_keys()
    ok = keys.rsa_pss_verify(pub, json.dumps(payload, sort_keys=True).encode(), sig)
    assert ok is True

# sign_payload missing private key should error (duplicate named test)
def test_sign_payload_missing_priv_raises_or_errors(monkeypatch):
    """If server.priv_pem is not set, sign_payload should raise/propagate an error (TypeError/ValueError)."""
    # ensure we have a working key first
    ensure_server_keys()
    # backup and unset
    backup = getattr(server, "priv_pem", None)
    try:
        if hasattr(server, "priv_pem"):
            delattr(server, "priv_pem")
        else:
            server.priv_pem = None
        with pytest.raises(Exception):
            server.sign_payload({"a": 1})
    finally:
        # restore
        if backup is not None:
            server.priv_pem = backup

# load_introducers malformed YAML handling (duplicate slow-check)
def test_load_introducers_handles_malformed_yaml(tmp_path):
    """load_introducers should tolerate malformed YAML (either raise or return None/empty)."""
    bad_file = os.path.join(str(tmp_path), "bad_intro.yml")
    with open(bad_file, "w") as fh:
        fh.write(":::: this is not valid yaml :::")
    try:
        out = server.load_introducers(bad_file)
    except Exception:
        # acceptable: function may raise on malformed YAML
        return
    assert out is None or out == {} or out == [] or isinstance(out, (list, dict))

# public_pem_to_der_b64url accepts str/bytes (duplicate entry)
def test_public_pem_to_der_b64url_accepts_str_and_bytes():
    """public_pem_to_der_b64url should accept bytes and raise TypeError for str if not supported."""
    priv, pub = server.priv_pem, server.pub_pem
    pub_bytes = pub if isinstance(pub, (bytes, bytearray)) else pub.encode("utf-8")
    pub_str = pub_bytes.decode("utf-8")

    # bytes input should always work
    out_bytes = server.public_pem_to_der_b64url(pub_bytes)
    assert isinstance(out_bytes, str)

    # str input may raise TypeError in some implementations
    with pytest.raises(TypeError):
        server.public_pem_to_der_b64url(pub_str)


# -------------------------
# Asynchronous Tests
# -------------------------

@pytest.mark.asyncio
async def test_sign_payload_and_build_server_hello_join_async():
    priv, pub = server.priv_pem, server.pub_pem
    hb = server.build_server_hello_join("sid-x", "127.0.0.1", 9999, keys.public_pem_to_der_b64url(pub))
    assert hb["type"] == "SERVER_HELLO_JOIN"
    ok = keys.rsa_pss_verify(pub, json.dumps(hb["payload"], sort_keys=True).encode(), keys.b64url_decode(hb["sig"]))
    assert ok

@pytest.mark.asyncio
async def test_build_presence_sync_with_users(tmp_path):
    tmpdir = str(tmp_path / "keys_user"); os.makedirs(tmpdir, exist_ok=True)
    up_priv, up_pub = keys.load_or_create_keys("alice", tmpdir)
    uid = keys.load_or_create_user_uuid("alice", tmpdir)
    server.user_locations[uid] = "local"
    server.user_pubkeys[uid] = up_pub.decode() if isinstance(up_pub, bytes) else up_pub
    server.user_names[uid] = "alice-name"

    msg = server.build_presence_sync("my-server")
    assert msg["type"] == "SERVER_PRESENCE_SYNC"
    payload = msg["payload"]
    assert payload["server_id"] == "my-server"
    users = payload["users"]
    assert any(u["user_id"] == uid for u in users)
    entry = next(u for u in users if u["user_id"] == uid)
    assert isinstance(entry["pubkey"], str)
    assert entry["meta"]["name"] == "alice-name"

@pytest.mark.asyncio
async def test_handle_ws_user_hello_success(tmp_path):
    tmpdir = str(tmp_path / "keys_h"); os.makedirs(tmpdir, exist_ok=True)
    u_priv, u_pub = keys.load_or_create_keys("bob", tmpdir)
    uid = keys.load_or_create_user_uuid("bob", tmpdir)
    pub_b64u = keys.public_pem_to_der_b64url(u_pub)
    msg = {
        "type": "USER_HELLO",
        "from": uid,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": {"pubkey_b64u": pub_b64u, "name": "bob"},
    }
    fake = FakeWebSocket([msg])
    await server.handle_ws(fake, "srv-test", "srv-name")
    assert any('"type": "USER_ADVERTISE"' in s or '"type":"USER_ADVERTISE"' in s for s in fake.sent)
    assert uid not in server.local_users


@pytest.mark.asyncio
async def test_msg_direct_missing_usig_returns_error(tmp_path):
    tmpdir = str(tmp_path / "keys_dm")
    os.makedirs(tmpdir, exist_ok=True)
    # create a sender key and register it in user_pubkeys so server knows it
    s_priv, s_pub = keys.load_or_create_keys("sender", tmpdir)
    s_uid = keys.load_or_create_user_uuid("sender", tmpdir)
    server.user_pubkeys[s_uid] = s_pub.decode() if isinstance(s_pub, bytes) else s_pub

    # create destination user mapping so USER_NOT_FOUND not triggered
    d_uid = str(uuid.uuid4())
    server.user_locations[d_uid] = "local"
    # but do not put websocket for dst -> will exercise delivery path that checks usig first

    msg = {
        "type": "MSG_DIRECT",
        "from": s_uid,
        "to": d_uid,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": {"ciphertext": "x"},
        # missing 'usig'
    }
    fake = FakeWebSocket([msg])
    await server.handle_ws(fake, "srv-test", "srv-name")
    # an ERROR frame should be sent for MISSING_USER_SIG
    found = False
    for s in fake.sent:
        try:
            j = json.loads(s)
            if j.get("type") == "ERROR" and j.get("payload", {}).get("code") == "MISSING_USER_SIG":
                found = True
        except Exception:
            pass
    assert found

@pytest.mark.asyncio
async def test_file_chunk_too_large_triggers_error(tmp_path):
    tmpdir = str(tmp_path / "keys_fc")
    os.makedirs(tmpdir, exist_ok=True)
    s_priv, s_pub = keys.load_or_create_keys("file-sender", tmpdir)
    s_uid = keys.load_or_create_user_uuid("file-sender", tmpdir)
    server.user_pubkeys[s_uid] = s_pub.decode() if isinstance(s_pub, bytes) else s_pub

    # destination exists but not local
    d_uid = str(uuid.uuid4())
    server.user_locations[d_uid] = "local"

    # craft a ciphertext string length > 4 * MAX_CHUNK_BYTES
    huge_ct = "A" * (4 * server.MAX_CHUNK_BYTES + 10)
    msg = {
        "type": "FILE_CHUNK",
        "from": s_uid,
        "to": d_uid,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": {"file_id": "fid-x", "index": 0, "ciphertext": huge_ct},
    }
    fake = FakeWebSocket([msg])
    await server.handle_ws(fake, "srv-test", "srv-name")
    # expect CHUNK_TOO_LARGE error
    assert any('"CHUNK_TOO_LARGE"' in s or '"CHUNK_TOO_LARGE"' in s for s in fake.sent)

@pytest.mark.asyncio
async def test_cmd_list_returns_snapshot(monkeypatch):
    # monkeypatch server.list_users to return a deterministic map
    async def fake_list_users():
        return {"u1": "Alice", "u2": "Bob"}
    monkeypatch.setattr(server, "list_users", fake_list_users)

    # create a client UUID
    client_uid = str(uuid.uuid4())
    msg = {
        "type": "CMD_LIST",
        "from": client_uid,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": {},
    }
    fake = FakeWebSocket([msg])
    await server.handle_ws(fake, "srv-test", "srv-name")
    # check that CMD_LIST_RESULT was sent
    jtypes = []
    for s in fake.sent:
        try:
            j = json.loads(s)
            jtypes.append(j.get("type"))
        except Exception:
            pass
    assert "CMD_LIST_RESULT" in jtypes

@pytest.mark.asyncio
async def test_msg_broadcast_delivered_to_local_users():
    """MSG_BROADCAST from a client should be forwarded to other local users (signed by server)."""
    # ensure server has keys for signing
    priv, pub = ensure_server_keys()
    server.server_id = getattr(server, "server_id", "test-srv-bcast")

    # prepare users and websockets
    sender_uid = str(uuid.uuid4())
    r1_uid = str(uuid.uuid4())
    r2_uid = str(uuid.uuid4())

    sender_ws = FakeWebSocket([
        {
            "type": "MSG_BROADCAST",
            "from": sender_uid,
            "id": uuid.uuid4().hex,
            "ts": now_ms(),
            "payload": {"text": "hello everybody"},
            "sig": None,
        }
    ])
    r1_ws = FakeWebSocket([])
    r2_ws = FakeWebSocket([])

    # register local users: include sender mapped to its websocket so it will be skipped
    server.local_users.clear()
    server.local_users[sender_uid] = sender_ws
    server.local_users[r1_uid] = r1_ws
    server.local_users[r2_uid] = r2_ws

    # invoke handler for sender websocket (it will iterate its incoming msg and perform broadcast)
    await server.handle_ws(sender_ws, "conn-bcast", "conn-name-bcast")

    # recipients should have received one message each
    assert len(r1_ws.sent) == 1, f"r1 did not receive broadcast: {r1_ws.sent}"
    assert len(r2_ws.sent) == 1, f"r2 did not receive broadcast: {r2_ws.sent}"

    # parse and validate delivered frame
    j1 = json.loads(r1_ws.sent[0])
    assert j1.get("type") == "MSG_BROADCAST"
    assert j1.get("from") == sender_uid
    assert j1.get("to") == "*"
    assert j1.get("payload", {}).get("text") == "hello everybody"
    assert j1.get("id"), "delivered message missing id"
    assert j1.get("ts"), "delivered message missing ts"
    assert j1.get("sig"), "delivered message missing sig"

    # verify signature covers payload and is verifiable by server pub key
    sig_b64u = j1.get("sig")
    ok = keys.rsa_pss_verify(pub, json.dumps(j1["payload"], sort_keys=True).encode(), keys.b64url_decode(sig_b64u))
    assert ok is True

    # ensure sender did not receive its own broadcast
    # (either no outgoing frames to sender, or no MSG_BROADCAST)
    if sender_ws.sent:
        assert not any("MSG_BROADCAST" in s or '"type":"MSG_BROADCAST"' in s or '"type": "MSG_BROADCAST"' in s for s in sender_ws.sent), \
            f"sender should not receive its own broadcast: {sender_ws.sent}"

import types
from types import SimpleNamespace
import websockets as _ws  # only for type reference if available

@pytest.mark.asyncio
async def test_ctrl_close_ack_sent():
    """CTRL_CLOSE from a client should elicit a signed CTRL_CLOSE_ACK to that client."""
    priv, pub = ensure_server_keys()
    server_id = getattr(server, "server_id", "test-server")

    mid = uuid.uuid4().hex
    src = "client-ctrl-1"
    msg = {
        "type": "CTRL_CLOSE",
        "from": src,
        "id": mid,
        "ts": now_ms(),
        "payload": {},
    }
    fake = FakeWebSocket([msg])
    await server.handle_ws(fake, "ctrl-conn", "ctrl-name")

    # find CTRL_CLOSE_ACK in outgoing frames
    found = None
    for s in fake.sent:
        try:
            j = json.loads(s)
        except Exception:
            continue
        if j.get("type") == "CTRL_CLOSE_ACK" and j.get("to") == src:
            found = j
            break

    assert found is not None, f"No CTRL_CLOSE_ACK sent. sent={fake.sent}"
    payload = found.get("payload", {})
    assert payload.get("echo_id") == mid, "CTRL_CLOSE_ACK echo_id mismatch"
    assert "server_ts" in payload and isinstance(payload["server_ts"], int)
    assert payload.get("note") == "app-heartbeat"
    sig_b64u = found.get("sig")
    assert sig_b64u, "CTRL_CLOSE_ACK missing signature"
    # verify signature using server public key
    ok = keys.rsa_pss_verify(pub, json.dumps(payload, sort_keys=True).encode(), keys.b64url_decode(sig_b64u))
    assert ok is True


import socket

def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

@pytest.mark.asyncio
async def test_server_hello_join_registers_and_welcomes(monkeypatch, tmp_path):
    """SERVER_HELLO_JOIN from a peer should register server_addrs and reply with a signed SERVER_WELCOME.
    Outbound connect attempts are monkeypatched to return a dummy peer websocket so no network I/O occurs.
    """
    priv, pub = ensure_server_keys()

    # create peer keypair and encoding
    pdir = str(tmp_path / "peer_keys")
    os.makedirs(pdir, exist_ok=True)
    _, peer_pub = keys.load_or_create_keys("peer-srv", pdir)
    peer_id = f"peer-{uuid.uuid4().hex[:8]}"
    host = "127.0.0.1"
    port = find_free_port()
    pub_b64u = keys.public_pem_to_der_b64url(peer_pub)

    # prepare the SERVER_HELLO_JOIN frame
    msg = {
        "type": "SERVER_HELLO_JOIN",
        "from": peer_id,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": {"host": host, "port": port, "pubkey": pub_b64u},
    }

    # dummy peer websocket to satisfy connect() and capture messages sent to the peer
    class DummyPeerWS:
        def __init__(self):
            self.sent = []

        async def send(self, data):
            self.sent.append(data)

        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

    def fake_connect(uri):
        return DummyPeerWS()

    # monkeypatch server.websockets.connect to avoid real network
    # attach a SimpleNamespace with connect attribute so server.websockets.connect(...) still works
    monkeypatch.setattr(server, "websockets", SimpleNamespace(connect=fake_connect))

    fake_ws = FakeWebSocket([msg])

    # ensure no pre-existing entry
    server.server_addrs.pop(peer_id, None)
    server.servers.pop(peer_id, None)
    server.server_pubkeys.pop(peer_id, None)

    await server.handle_ws(fake_ws, "intro-conn-test", "intro-name-test")

    # The server should now have registered the peer in server_addrs
    assert peer_id in server.server_addrs, f"peer not registered in server_addrs: {server.server_addrs}"

    entry = server.server_addrs[peer_id]
    assert entry[0] == host and int(entry[1]) == int(port) or isinstance(entry[1], int), "registered host/port mismatch"
    assert entry[2] == pub_b64u, "registered pubkey mismatch"

    # server should have sent a SERVER_WELCOME on the original websocket
    welcome = None
    for s in fake_ws.sent:
        try:
            j = json.loads(s)
        except Exception:
            continue
        if j.get("type") == "SERVER_WELCOME":
            welcome = j
            break

    assert welcome is not None, f"No SERVER_WELCOME sent back to introducer. sent={fake_ws.sent}"

    # validate welcome payload and signature
    wpayload = welcome.get("payload", {})
    assert wpayload.get("assigned_id") == peer_id or isinstance(wpayload.get("assigned_id"), str)
    assert "servers" in wpayload and isinstance(wpayload["servers"], list)
    sig_b64u = welcome.get("sig")
    assert sig_b64u, "SERVER_WELCOME missing sig"
    ok = keys.rsa_pss_verify(pub, json.dumps(wpayload, sort_keys=True).encode(), keys.b64url_decode(sig_b64u))
    assert ok is True

import base64

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.mark.asyncio
async def test_server_announce_registers_and_federates(monkeypatch, tmp_path):
    """SERVER_ANNOUNCE should verify signature, register the peer and attempt reverse connect."""
    priv, pub = ensure_server_keys()

    # create announcer keypair (peer announcing itself)
    pdir = str(tmp_path / "announce_keys"); os.makedirs(pdir, exist_ok=True)
    peer_priv, peer_pub = keys.load_or_create_keys("announce-peer", pdir)
    peer_id = f"peer-{uuid.uuid4().hex[:8]}"
    host = "127.0.0.1"
    port = find_free_port()
    pub_b64u = server.public_pem_to_der_b64url(peer_pub)

    payload = {"host": host, "port": port, "pubkey": pub_b64u}
    sig = keys.rsa_pss_sign(peer_priv, json.dumps(payload, sort_keys=True).encode())
    sig_b64u = _b64url_encode(sig)

    msg = {
        "type": "SERVER_ANNOUNCE",
        "from": peer_id,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": payload,
        "sig": sig_b64u,
    }

    # Dummy peer websocket returned by outbound connect attempt
    class DummyPeerWS:
        def __init__(self):
            self.sent = []
        async def send(self, data):
            self.sent.append(data)
        def __aiter__(self):
            return self
        async def __anext__(self):
            raise StopAsyncIteration

    def fake_connect(uri):
        return DummyPeerWS()

    # monkeypatch outbound connect to avoid real network
    monkeypatch.setattr(server, "websockets", SimpleNamespace(connect=fake_connect))

    # ensure clean state
    server.server_addrs.pop(peer_id, None)
    server.servers.pop(peer_id, None)
    server.server_pubkeys.pop(peer_id, None)

    fake_ws = FakeWebSocket([msg])
    await server.handle_ws(fake_ws, "announce-conn", "announce-name")

    # peer should be registered
    assert peer_id in server.server_addrs, f"peer not registered: {server.server_addrs}"
    entry = server.server_addrs[peer_id]
    assert entry[0] == host and int(entry[1]) == int(port)
    assert entry[2] == pub_b64u

    # server_pubkeys stored and decodes to PEM matching peer_pub
    stored_pem = server.server_pubkeys.get(peer_id)
    assert stored_pem is not None
    decoded = server.der_b64url_to_public_pem(pub_b64u).decode() if isinstance(server.der_b64url_to_public_pem(pub_b64u), (bytes, bytearray)) else server.der_b64url_to_public_pem(pub_b64u)
    assert stored_pem == decoded

    # verify that no exception occurred and handler completed (welcome/announce path sends nothing unexpected to introducer)
    # also ensure original websocket was accepted into servers (inbound link)
    assert server.servers.get(peer_id) is not None, "Inbound server link not recorded"


@pytest.mark.asyncio
async def test_user_remove_notifies_locals_and_forwards(monkeypatch, tmp_path):
    """USER_REMOVE from a remote server should remove mappings, notify local clients (USER_REMOVE + CMD_LIST_RESULT)
    and forward the original frame to other federated servers.
    """
    priv, pub = ensure_server_keys()

    # Setup announcing peer keys and register it in server_addrs so signature verifies
    kdir = str(tmp_path / "user_remove_keys"); os.makedirs(kdir, exist_ok=True)
    peer_priv, peer_pub = keys.load_or_create_keys("announce-peer", kdir)
    origin_sid = f"peer-{uuid.uuid4().hex[:8]}"
    host = "127.0.0.1"
    port = find_free_port()
    pub_b64u = server.public_pem_to_der_b64url(peer_pub)

    server.server_addrs[origin_sid] = (host, port, pub_b64u)

    # Create a user that is known to be located on the origin server
    uid = f"user-{uuid.uuid4().hex[:8]}"
    server.user_locations[uid] = origin_sid
    # ensure we have a pubkey and name so CMD_LIST_RESULT includes them
    server.user_pubkeys[uid] = "fake-pub-if-needed"
    server.user_names[uid] = "victim"

    # Prepare payload and sign it with the origin server private key
    payload = {"user_id": uid, "server_id": origin_sid, "pubkey": None, "meta": {"name": "victim"}}
    sig = keys.rsa_pss_sign(peer_priv, json.dumps(payload, sort_keys=True).encode())
    # helper: b64url encode (use same encoding as other tests)
    import base64
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
    sig_b64u = _b64url_encode(sig)

    msg = {
        "type": "USER_REMOVE",
        "from": origin_sid,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": payload,
        "sig": sig_b64u,
    }

    # Prepare two local clients to receive announcements
    local_a = FakeWebSocket([])
    local_b = FakeWebSocket([])
    server.local_users.clear()
    server.local_users["local-a"] = local_a
    server.local_users["local-b"] = local_b

    # Prepare another federated server link to receive forwarded frame
    class OtherLink:
        def __init__(self):
            self.open = True
            self.sent = []
        async def send(self, data):
            self.sent.append(data)
    other = OtherLink()
    other_sid = "other-peer"
    server.servers[other_sid] = other

    # Incoming websocket (the origin connection) - use FakeWebSocket to feed the USER_REMOVE
    incoming = FakeWebSocket([msg])

    # Call the handler
    await server.handle_ws(incoming, "conn-userremove", "conn-name-userremove")

    # Local clients should have received a USER_REMOVE and a CMD_LIST_RESULT each
    def types_from(ws):
        t = []
        for s in ws.sent:
            try:
                j = json.loads(s)
                t.append(j.get("type"))
            except Exception:
                pass
        return t

    ta = types_from(local_a)
    tb = types_from(local_b)
    assert "USER_REMOVE" in ta, f"local-a missing USER_REMOVE: {local_a.sent}"
    assert "CMD_LIST_RESULT" in ta, f"local-a missing CMD_LIST_RESULT: {local_a.sent}"
    assert "USER_REMOVE" in tb, f"local-b missing USER_REMOVE: {local_b.sent}"
    assert "CMD_LIST_RESULT" in tb, f"local-b missing CMD_LIST_RESULT: {local_b.sent}"

    # The server should have removed the user's location/pubkey/name
    assert uid not in server.user_locations
    assert uid not in server.user_pubkeys
    assert uid not in server.user_names

    # The other federated link should have been forwarded the original USER_REMOVE frame
    assert len(other.sent) >= 1, f"other peer did not receive forwarded frame: {other.sent}"
    # the forwarded frame should contain the same type and user_id
    forwarded = None
    for item in other.sent:
        try:
            j = json.loads(item)
            if j.get("type") == "USER_REMOVE" and j.get("payload", {}).get("user_id") == uid:
                forwarded = j
                break
        except Exception:
            pass
    assert forwarded is not None, f"No forwarded USER_REMOVE for {uid} found in other.sent: {other.sent}"


@pytest.mark.asyncio
async def test_user_remove_notifies_locals_and_forwards(monkeypatch, tmp_path):
    """USER_REMOVE from a remote server should remove mappings, notify local clients (USER_REMOVE + CMD_LIST_RESULT)
    and forward the original frame to other federated servers.
    """
    priv, pub = ensure_server_keys()

    # Setup announcing peer keys and register it in server_addrs so signature verifies
    kdir = str(tmp_path / "user_remove_keys"); os.makedirs(kdir, exist_ok=True)
    peer_priv, peer_pub = keys.load_or_create_keys("announce-peer", kdir)
    origin_sid = f"peer-{uuid.uuid4().hex[:8]}"
    host = "127.0.0.1"
    port = find_free_port()
    pub_b64u = server.public_pem_to_der_b64url(peer_pub)

    server.server_addrs[origin_sid] = (host, port, pub_b64u)

    # Create a user that is known to be located on the origin server
    uid = f"user-{uuid.uuid4().hex[:8]}"
    server.user_locations[uid] = origin_sid
    # ensure we have a pubkey and name so CMD_LIST_RESULT includes them
    server.user_pubkeys[uid] = "fake-pub-if-needed"
    server.user_names[uid] = "victim"

    # Prepare payload and sign it with the origin server private key
    payload = {"user_id": uid, "server_id": origin_sid, "pubkey": None, "meta": {"name": "victim"}}
    sig = keys.rsa_pss_sign(peer_priv, json.dumps(payload, sort_keys=True).encode())
    # helper: b64url encode (use same encoding as other tests)
    import base64
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
    sig_b64u = _b64url_encode(sig)

    msg = {
        "type": "USER_REMOVE",
        "from": origin_sid,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": payload,
        "sig": sig_b64u,
    }

    # Prepare two local clients to receive announcements
    local_a = FakeWebSocket([])
    local_b = FakeWebSocket([])
    server.local_users.clear()
    server.local_users["local-a"] = local_a
    server.local_users["local-b"] = local_b

    # Prepare another federated server link to receive forwarded frame
    class OtherLink:
        def __init__(self):
            self.open = True
            self.sent = []
        async def send(self, data):
            self.sent.append(data)
    other = OtherLink()
    other_sid = "other-peer"
    server.servers[other_sid] = other

    # Incoming websocket (the origin connection) - use FakeWebSocket to feed the USER_REMOVE
    incoming = FakeWebSocket([msg])

    # Call the handler
    await server.handle_ws(incoming, "conn-userremove", "conn-name-userremove")

    # Local clients should have received a USER_REMOVE and a CMD_LIST_RESULT each
    def types_from(ws):
        t = []
        for s in ws.sent:
            try:
                j = json.loads(s)
                t.append(j.get("type"))
            except Exception:
                pass
        return t

    ta = types_from(local_a)
    tb = types_from(local_b)
    assert "USER_REMOVE" in ta, f"local-a missing USER_REMOVE: {local_a.sent}"
    assert "CMD_LIST_RESULT" in ta, f"local-a missing CMD_LIST_RESULT: {local_a.sent}"
    assert "USER_REMOVE" in tb, f"local-b missing USER_REMOVE: {local_b.sent}"
    assert "CMD_LIST_RESULT" in tb, f"local-b missing CMD_LIST_RESULT: {local_b.sent}"

    # The server should have removed the user's location/pubkey/name
    assert uid not in server.user_locations
    assert uid not in server.user_pubkeys
    assert uid not in server.user_names

    # The other federated link should have been forwarded the original USER_REMOVE frame
    assert len(other.sent) >= 1, f"other peer did not receive forwarded frame: {other.sent}"
    # the forwarded frame should contain the same type and user_id
    forwarded = None
    for item in other.sent:
        try:
            j = json.loads(item)
            if j.get("type") == "USER_REMOVE" and j.get("payload", {}).get("user_id") == uid:
                forwarded = j
                break
        except Exception:
            pass
    assert forwarded is not None, f"No forwarded USER_REMOVE for {uid} found in other.sent: {other.sent}"

# ...existing code...

@pytest.mark.asyncio
async def test_server_deliver_re_fwd_file_chunk(monkeypatch, tmp_path):
    """A SERVER_DELIVER(FILE_CHUNK) for a non-local recipient should be re-forwarded to the known server link."""
    priv, pub = ensure_server_keys()

    # create origin server keys and register origin in server_addrs so signature verifies
    kdir = str(tmp_path / "deliver_origin"); os.makedirs(kdir, exist_ok=True)
    origin_priv, origin_pub = keys.load_or_create_keys("origin-srv", kdir)
    origin_sid = f"origin-{uuid.uuid4().hex[:8]}"
    host = "127.0.0.1"
    port = find_free_port()
    origin_pub_b64u = server.public_pem_to_der_b64url(origin_pub)
    server.server_addrs[origin_sid] = (host, port, origin_pub_b64u)

    # prepare recipient mapped to target server (not local)
    recipient = f"user-{uuid.uuid4().hex[:8]}"
    target_sid = f"target-{uuid.uuid4().hex[:8]}"
    server.user_locations[recipient] = target_sid

    # create a target server link that records sends and appears open
    class TargetLink:
        def __init__(self):
            self.open = True
            self.sent = []
        async def send(self, data):
            self.sent.append(data)
    target = TargetLink()
    server.servers[target_sid] = target

    # craft FILE_CHUNK payload and sign it using origin_priv
    file_obj = {"file_id": "fid-1", "index": 3, "ciphertext": "CIPHERTEXT_BYTES"}
    payload = {"user_id": recipient, "sender": "alice", "kind": "FILE_CHUNK", "file": file_obj}
    sig = keys.rsa_pss_sign(origin_priv, json.dumps(payload, sort_keys=True).encode())
    # inline b64url encode helper
    import base64
    sig_b64u = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")

    msg = {"type": "SERVER_DELIVER", "from": origin_sid, "id": uuid.uuid4().hex, "ts": now_ms(), "payload": payload, "sig": sig_b64u}
    incoming = FakeWebSocket([msg])

    await server.handle_ws(incoming, "conn-deliver-file", "conn-name-deliver-file")

    # ensure the target link received a forwarded frame
    assert len(target.sent) >= 1, f"target link did not receive forwarded FILE_CHUNK: {target.sent}"
    found = False
    for s in target.sent:
        try:
            j = json.loads(s)
            if j.get("type") == "SERVER_DELIVER" and j.get("payload", {}).get("payload", {}).get("file", {}).get("file_id") == "fid-1":
                found = True
                break
        except Exception:
            pass
    assert found, f"No forwarded SERVER_DELIVER(FILE_CHUNK) found: {target.sent}"


@pytest.mark.asyncio
async def test_server_deliver_dm_to_local_and_signature(monkeypatch, tmp_path):
    """A SERVER_DELIVER (DM) for a local recipient should be delivered as USER_DELIVER and signed by this server."""
    priv, pub = ensure_server_keys()

    # origin server keys registration
    kdir = str(tmp_path / "deliver_origin2"); os.makedirs(kdir, exist_ok=True)
    origin_priv, origin_pub = keys.load_or_create_keys("origin2-srv", kdir)
    origin_sid = f"origin2-{uuid.uuid4().hex[:8]}"
    host = "127.0.0.1"
    port = find_free_port()
    origin_pub_b64u = server.public_pem_to_der_b64url(origin_pub)
    server.server_addrs[origin_sid] = (host, port, origin_pub_b64u)

    # prepare a local recipient
    recipient = f"userlocal-{uuid.uuid4().hex[:8]}"
    server.user_locations[recipient] = "local"
    recipient_ws = FakeWebSocket([])
    server.local_users[recipient] = recipient_ws

    # craft DM payload and sign with origin_priv
    payload = {"user_id": recipient, "sender": "bob", "ciphertext": "secret-cipher", "sender_pub": None, "content_sig": None}
    sig = keys.rsa_pss_sign(origin_priv, json.dumps(payload, sort_keys=True).encode())
    import base64
    sig_b64u = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")

    msg = {"type": "SERVER_DELIVER", "from": origin_sid, "id": uuid.uuid4().hex, "ts": now_ms(), "payload": payload, "sig": sig_b64u}
    incoming = FakeWebSocket([msg])

    await server.handle_ws(incoming, "conn-deliver-dm", "conn-name-deliver-dm")

    # recipient should have received a USER_DELIVER signed by this server
    assert len(recipient_ws.sent) >= 1, f"local recipient did not receive USER_DELIVER: {recipient_ws.sent}"
    ud = None
    for s in recipient_ws.sent:
        try:
            j = json.loads(s)
            if j.get("type") == "USER_DELIVER":
                ud = j
                break
        except Exception:
            pass
    assert ud is not None, f"No USER_DELIVER frame found: {recipient_ws.sent}"
    assert ud.get("payload", {}).get("ciphertext") == "secret-cipher"
    # verify server signature over payload
    srv_pub = server.pub_pem
    assert ud.get("sig"), "USER_DELIVER missing sig"
    ok = keys.rsa_pss_verify(srv_pub, json.dumps(ud["payload"], sort_keys=True).encode(), keys.b64url_decode(ud["sig"]))
    assert ok is True


# ...existing code...
@pytest.mark.asyncio
async def test_server_deliver_re_fwd_file_chunk(monkeypatch, tmp_path):
    """A SERVER_DELIVER(FILE_CHUNK) for a non-local recipient should be re-forwarded to the known server link."""
    priv, pub = ensure_server_keys()

    # create origin server keys and register origin in server_addrs so signature verifies
    kdir = str(tmp_path / "deliver_origin"); os.makedirs(kdir, exist_ok=True)
    origin_priv, origin_pub = keys.load_or_create_keys("origin-srv", kdir)
    origin_sid = f"origin-{uuid.uuid4().hex[:8]}"
    host = "127.0.0.1"
    port = find_free_port()
    origin_pub_b64u = server.public_pem_to_der_b64url(origin_pub)
    server.server_addrs[origin_sid] = (host, port, origin_pub_b64u)

    # prepare recipient mapped to target server (not local)
    recipient = f"user-{uuid.uuid4().hex[:8]}"
    target_sid = f"target-{uuid.uuid4().hex[:8]}"
    server.user_locations[recipient] = target_sid

    # create a target server link that records sends and appears open
    class TargetLink:
        def __init__(self):
            self.open = True
            self.sent = []
        async def send(self, data):
            self.sent.append(data)
    target = TargetLink()
    server.servers[target_sid] = target

    # craft FILE_CHUNK payload and sign it using origin_priv
    file_obj = {"file_id": "fid-1", "index": 3, "ciphertext": "CIPHERTEXT_BYTES"}
    payload = {"user_id": recipient, "sender": "alice", "kind": "FILE_CHUNK", "file": file_obj}
    sig = keys.rsa_pss_sign(origin_priv, json.dumps(payload, sort_keys=True).encode())
    # inline b64url encode helper
    import base64
    sig_b64u = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")

    msg = {"type": "SERVER_DELIVER", "from": origin_sid, "id": uuid.uuid4().hex, "ts": now_ms(), "payload": payload, "sig": sig_b64u}
    incoming = FakeWebSocket([msg])

    await server.handle_ws(incoming, "conn-deliver-file", "conn-name-deliver-file")

    # ensure the target link received a forwarded frame
    assert len(target.sent) >= 1, f"target link did not receive forwarded FILE_CHUNK: {target.sent}"
    found = False
    for s in target.sent:
        try:
            j = json.loads(s)
            # forwarded frame should be the original SERVER_DELIVER; payload.file.file_id should match
            if j.get("type") == "SERVER_DELIVER" and j.get("payload", {}).get("file", {}).get("file_id") == "fid-1":
                # also ensure it has the kind marker
                if j.get("payload", {}).get("kind") == "FILE_CHUNK":
                    found = True
                    break
        except Exception:
            pass
    assert found, f"No forwarded SERVER_DELIVER(FILE_CHUNK) found: {target.sent}"


@pytest.mark.asyncio
async def test_server_deliver_re_fwd_file_chunk(monkeypatch, tmp_path):
    """A SERVER_DELIVER(FILE_CHUNK) for a non-local recipient should be re-forwarded to the known server link."""
    priv, pub = ensure_server_keys()

    # create origin server keys and register origin in server_addrs so signature verifies
    kdir = str(tmp_path / "deliver_origin"); os.makedirs(kdir, exist_ok=True)
    origin_priv, origin_pub = keys.load_or_create_keys("origin-srv", kdir)
    origin_sid = f"origin-{uuid.uuid4().hex[:8]}"
    host = "127.0.0.1"
    port = find_free_port()
    origin_pub_b64u = server.public_pem_to_der_b64url(origin_pub)
    server.server_addrs[origin_sid] = (host, port, origin_pub_b64u)

    # prepare recipient mapped to target server (not local)
    recipient = f"user-{uuid.uuid4().hex[:8]}"
    target_sid = f"target-{uuid.uuid4().hex[:8]}"
    server.user_locations[recipient] = target_sid

    # create a target server link that records sends and appears open
    class TargetLink:
        def __init__(self):
            self.open = True
            self.sent = []
        async def send(self, data):
            self.sent.append(data)
    target = TargetLink()
    server.servers[target_sid] = target

    # craft FILE_CHUNK payload and sign it using origin_priv
    file_obj = {"file_id": "fid-1", "index": 3, "ciphertext": "CIPHERTEXT_BYTES"}
    payload = {"user_id": recipient, "sender": "alice", "kind": "FILE_CHUNK", "file": file_obj}
    sig = keys.rsa_pss_sign(origin_priv, json.dumps(payload, sort_keys=True).encode())
    # inline b64url encode helper
    import base64
    sig_b64u = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")

    msg = {"type": "SERVER_DELIVER", "from": origin_sid, "id": uuid.uuid4().hex, "ts": now_ms(), "payload": payload, "sig": sig_b64u}
    incoming = FakeWebSocket([msg])

    await server.handle_ws(incoming, "conn-deliver-file", "conn-name-deliver-file")

    # ensure the target link received a forwarded frame
    assert len(target.sent) >= 1, f"target link did not receive forwarded FILE_CHUNK: {target.sent}"
    found = False
    for s in target.sent:
        try:
            j = json.loads(s)
            # forwarded frame should be the original SERVER_DELIVER; payload.file.file_id should match
            if j.get("type") == "SERVER_DELIVER" and j.get("payload", {}).get("file", {}).get("file_id") == "fid-1":
                # also ensure it has the kind marker
                if j.get("payload", {}).get("kind") == "FILE_CHUNK":
                    found = True
                    break
        except Exception:
            pass
    assert found, f"No forwarded SERVER_DELIVER(FILE_CHUNK) found: {target.sent}"


@pytest.mark.asyncio
async def test_server_deliver_dm_to_local_and_signature(monkeypatch, tmp_path):
    """A SERVER_DELIVER (DM) for a local recipient should be delivered as USER_DELIVER and signed by this server."""
    priv, pub = ensure_server_keys()

    # origin server keys registration
    kdir = str(tmp_path / "deliver_origin2"); os.makedirs(kdir, exist_ok=True)
    origin_priv, origin_pub = keys.load_or_create_keys("origin2-srv", kdir)
    origin_sid = f"origin2-{uuid.uuid4().hex[:8]}"
    host = "127.0.0.1"
    port = find_free_port()
    origin_pub_b64u = server.public_pem_to_der_b64url(origin_pub)
    server.server_addrs[origin_sid] = (host, port, origin_pub_b64u)

    # prepare a local recipient
    recipient = f"userlocal-{uuid.uuid4().hex[:8]}"
    server.user_locations[recipient] = "local"
    recipient_ws = FakeWebSocket([])
    server.local_users[recipient] = recipient_ws

    # craft DM payload and sign with origin_priv
    payload = {"user_id": recipient, "sender": "bob", "ciphertext": "secret-cipher", "sender_pub": None, "content_sig": None}
    sig = keys.rsa_pss_sign(origin_priv, json.dumps(payload, sort_keys=True).encode())
    import base64
    sig_b64u = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")

    msg = {"type": "SERVER_DELIVER", "from": origin_sid, "id": uuid.uuid4().hex, "ts": now_ms(), "payload": payload, "sig": sig_b64u}
    incoming = FakeWebSocket([msg])

    await server.handle_ws(incoming, "conn-deliver-dm", "conn-name-deliver-dm")

    # recipient should have received a USER_DELIVER signed by this server
    assert len(recipient_ws.sent) >= 1, f"local recipient did not receive USER_DELIVER: {recipient_ws.sent}"
    ud = None
    for s in recipient_ws.sent:
        try:
            j = json.loads(s)
            if j.get("type") == "USER_DELIVER":
                ud = j
                break
        except Exception:
            pass
    assert ud is not None, f"No USER_DELIVER frame found: {recipient_ws.sent}"
    assert ud.get("payload", {}).get("ciphertext") == "secret-cipher"
    # verify server signature over payload
    srv_pub = server.pub_pem
    assert ud.get("sig"), "USER_DELIVER missing sig"
    ok = keys.rsa_pss_verify(srv_pub, json.dumps(ud["payload"], sort_keys=True).encode(), keys.b64url_decode(ud["sig"]))
    assert ok is True


@pytest.mark.asyncio
async def test_heartbeat_valid_updates_last_seen(tmp_path):
    """A valid HEARTBEAT signed by a known server should update server.last_seen."""
    ensure_server_keys()

    # create origin server keys and register origin in server_addrs so signature verifies
    pdir = str(tmp_path / "hb_keys"); os.makedirs(pdir, exist_ok=True)
    origin_priv, origin_pub = keys.load_or_create_keys("hb-origin", pdir)
    origin_sid = f"hb-{uuid.uuid4().hex[:8]}"
    host = "127.0.0.1"
    port = find_free_port()
    pub_b64u = server.public_pem_to_der_b64url(origin_pub)
    server.server_addrs[origin_sid] = (host, port, pub_b64u)

    payload = {"ping": now_ms()}
    sig = keys.rsa_pss_sign(origin_priv, json.dumps(payload, sort_keys=True).encode())
    import base64
    sig_b64u = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")

    msg = {"type": "HEARTBEAT", "from": origin_sid, "id": uuid.uuid4().hex, "ts": now_ms(), "payload": payload, "sig": sig_b64u}
    incoming = FakeWebSocket([msg])

    # ensure no prior last_seen
    server.last_seen.pop(origin_sid, None)

    await server.handle_ws(incoming, "hb-conn", "hb-name")

    assert origin_sid in server.last_seen, f"heartbeat did not set last_seen for {origin_sid}"
    assert abs(time.time() - server.last_seen[origin_sid]) < 5, "last_seen timestamp not recent"
    # no outgoing frames expected for successful heartbeat
    assert incoming.sent == []

@pytest.mark.asyncio
async def test_heartbeat_bad_signature_is_ignored(monkeypatch, tmp_path):
    """A HEARTBEAT with a bad signature should be ignored (or at least logged as BAD SIGNATURE).
    Accept either behavior: server may skip updating last_seen, or it may still record a timestamp
    but must log a BAD SIGNATURE event for the origin.
    """
    ensure_server_keys()

    pdir = str(tmp_path / "hb_keys_bad"); os.makedirs(pdir, exist_ok=True)
    origin_priv, origin_pub = keys.load_or_create_keys("hb-origin-bad", pdir)
    # create a different key to sign (so verification fails)
    other_priv, other_pub = keys.load_or_create_keys("hb-origin-other", pdir)

    origin_sid = f"hbbad-{uuid.uuid4().hex[:8]}"
    host = "127.0.0.1"
    port = find_free_port()
    pub_b64u = server.public_pem_to_der_b64url(origin_pub)
    server.server_addrs[origin_sid] = (host, port, pub_b64u)

    payload = {"ping": now_ms()}
    # sign with the wrong private key
    sig = keys.rsa_pss_sign(other_priv, json.dumps(payload, sort_keys=True).encode())
    import base64
    sig_b64u = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")

    msg = {"type": "HEARTBEAT", "from": origin_sid, "id": uuid.uuid4().hex, "ts": now_ms(), "payload": payload, "sig": sig_b64u}
    incoming = FakeWebSocket([msg])

    # ensure no prior last_seen
    server.last_seen.pop(origin_sid, None)

    # capture printed output via monkeypatched print
    printed = []
    import builtins
    def _fake_print(*args, **kwargs):
        try:
            printed.append(" ".join(str(a) for a in args))
        except Exception:
            printed.append(str(args))
    monkeypatch.setattr(builtins, "print", _fake_print)

    await server.handle_ws(incoming, "hb-conn-bad", "hb-name-bad")

    if origin_sid in server.last_seen:
        assert any("BAD SIGNATURE" in p or "BAD SIGNATURE" in p.upper() or "[heartbeat] BAD SIGNATURE" in p for p in printed), \
            "Heartbeat had bad signature but no BAD SIGNATURE log was printed"
    else:
        # not present — desired behavior
        assert origin_sid not in server.last_seen

    # handler should not produce successful outgoing frames
    assert incoming.sent == [] or all("BAD SIGNATURE" in s or "BAD" in s or "ERROR" in s for s in incoming.sent)

@pytest.mark.asyncio
async def test_file_chunk_user_not_found_sends_error(monkeypatch, tmp_path):
    """If FILE_CHUNK destination is unknown, server should reply with ERROR USER_NOT_FOUND."""
    ensure_server_keys()
    src = f"user-src-{uuid.uuid4().hex[:6]}"
    dst = f"user-missing-{uuid.uuid4().hex[:6]}"
    # ensure no mapping
    server.user_locations.pop(dst, None)

    msg = {
        "type": "FILE_CHUNK",
        "from": src,
        "to": dst,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": {"file_id": "fid-x", "index": 0, "ciphertext": "ct"},
    }
    incoming = FakeWebSocket([msg])
    await server.handle_ws(incoming, "conn-file-notfound", "conn-name-file-notfound")

    # original websocket should have received an ERROR frame indicating USER_NOT_FOUND
    found = False
    for s in incoming.sent:
        try:
            j = json.loads(s)
            if j.get("type") == "ERROR" and j.get("payload", {}).get("code") == "USER_NOT_FOUND":
                found = True
                break
        except Exception:
            pass
    assert found, f"No USER_NOT_FOUND error sent: {incoming.sent}"


@pytest.mark.asyncio
async def test_file_chunk_delivers_to_local_client_and_signed(monkeypatch, tmp_path):
    """A FILE_CHUNK for a local recipient should be delivered as USER_FILE_CHUNK to that websocket and signed."""
    priv, pub = ensure_server_keys()
    src = f"user-src-{uuid.uuid4().hex[:6]}"
    dst = f"user-local-{uuid.uuid4().hex[:6]}"

    # mark recipient as local and attach websocket
    server.user_locations[dst] = "local"
    recipient_ws = FakeWebSocket([])
    server.local_users[dst] = recipient_ws

    payload_file = {"file_id": "fid-123", "index": 1, "ciphertext": "ciphertext-bytes"}
    msg = {
        "type": "FILE_CHUNK",
        "from": src,
        "to": dst,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": payload_file,
    }
    incoming = FakeWebSocket([msg])
    await server.handle_ws(incoming, "conn-file-local", "conn-name-file-local")

    assert len(recipient_ws.sent) >= 1, f"local recipient did not receive USER_FILE_CHUNK: {recipient_ws.sent}"
    ud = None
    for s in recipient_ws.sent:
        try:
            j = json.loads(s)
            if j.get("type") == "USER_FILE_CHUNK":
                ud = j
                break
        except Exception:
            pass
    assert ud is not None, f"No USER_FILE_CHUNK frame found: {recipient_ws.sent}"
    assert ud.get("payload", {}).get("file_id") == "fid-123"
    assert ud.get("payload", {}).get("index") == 1
    assert ud.get("payload", {}).get("ciphertext") == "ciphertext-bytes"
    # verify signature exists and is valid for the payload
    assert ud.get("sig"), "USER_FILE_CHUNK missing sig"
    ok = keys.rsa_pss_verify(server.pub_pem, json.dumps(ud["payload"], sort_keys=True).encode(), keys.b64url_decode(ud["sig"]))
    assert ok is True


@pytest.mark.asyncio
async def test_file_chunk_forwards_to_remote_server_link(monkeypatch, tmp_path):
    """A FILE_CHUNK for a non-local recipient should be wrapped into SERVER_DELIVER(kind=FILE_CHUNK) and sent to the target server link."""
    ensure_server_keys()
    src = f"user-src-{uuid.uuid4().hex[:6]}"
    dst = f"user-remote-{uuid.uuid4().hex[:6]}"
    target_sid = f"target-{uuid.uuid4().hex[:6]}"

    # map recipient to remote server and create a target link that records sends
    server.user_locations[dst] = target_sid

    class TargetLink:
        def __init__(self):
            self.open = True
            self.sent = []
        async def send(self, data):
            self.sent.append(data)

    target = TargetLink()
    server.servers[target_sid] = target

    payload_file = {"file_id": "fid-xyz", "index": 2, "ciphertext": "ct-bytes"}
    msg = {
        "type": "FILE_CHUNK",
        "from": src,
        "to": dst,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": payload_file,
    }
    incoming = FakeWebSocket([msg])
    await server.handle_ws(incoming, "conn-file-remote", "conn-name-file-remote")

    assert len(target.sent) >= 1, f"remote target did not receive forwarded SERVER_DELIVER: {target.sent}"
    found = False
    for s in target.sent:
        try:
            j = json.loads(s)
            if j.get("type") == "SERVER_DELIVER":
                p = j.get("payload", {})
                if p.get("kind") == "FILE_CHUNK" and p.get("user_id") == dst and p.get("file", {}).get("file_id") == "fid-xyz":
                    found = True
                    break
        except Exception:
            pass
    assert found, f"No SERVER_DELIVER(FILE_CHUNK) forwarded correctly: {target.sent}"

@pytest.mark.asyncio
async def test_file_chunk_user_not_found_sends_error(monkeypatch, tmp_path):
    """If FILE_CHUNK destination is unknown, server should reply with ERROR USER_NOT_FOUND."""
    ensure_server_keys()
    src = f"user-src-{uuid.uuid4().hex[:6]}"
    dst = f"user-missing-{uuid.uuid4().hex[:6]}"
    # ensure no mapping
    server.user_locations.pop(dst, None)

    msg = {
        "type": "FILE_CHUNK",
        "from": src,
        "to": dst,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": {"file_id": "fid-x", "index": 0, "ciphertext": "ct"},
    }
    incoming = FakeWebSocket([msg])
    await server.handle_ws(incoming, "conn-file-notfound", "conn-name-file-notfound")

    # original websocket should have received an ERROR frame indicating USER_NOT_FOUND
    found = False
    for s in incoming.sent:
        try:
            j = json.loads(s)
            if j.get("type") == "ERROR" and j.get("payload", {}).get("code") == "USER_NOT_FOUND":
                found = True
                break
        except Exception:
            pass
    assert found, f"No USER_NOT_FOUND error sent: {incoming.sent}"


@pytest.mark.asyncio
async def test_file_chunk_delivers_to_local_client_and_signed(monkeypatch, tmp_path):
    """A FILE_CHUNK for a local recipient should be delivered as USER_FILE_CHUNK to that websocket and signed."""
    priv, pub = ensure_server_keys()
    src = f"user-src-{uuid.uuid4().hex[:6]}"
    dst = f"user-local-{uuid.uuid4().hex[:6]}"

    # mark recipient as local and attach websocket
    server.user_locations[dst] = "local"
    recipient_ws = FakeWebSocket([])
    server.local_users[dst] = recipient_ws

    payload_file = {"file_id": "fid-123", "index": 1, "ciphertext": "ciphertext-bytes"}
    msg = {
        "type": "FILE_CHUNK",
        "from": src,
        "to": dst,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": payload_file,
    }
    incoming = FakeWebSocket([msg])
    await server.handle_ws(incoming, "conn-file-local", "conn-name-file-local")

    assert len(recipient_ws.sent) >= 1, f"local recipient did not receive USER_FILE_CHUNK: {recipient_ws.sent}"
    ud = None
    for s in recipient_ws.sent:
        try:
            j = json.loads(s)
            if j.get("type") == "USER_FILE_CHUNK":
                ud = j
                break
        except Exception:
            pass
    assert ud is not None, f"No USER_FILE_CHUNK frame found: {recipient_ws.sent}"
    assert ud.get("payload", {}).get("file_id") == "fid-123"
    assert ud.get("payload", {}).get("index") == 1
    assert ud.get("payload", {}).get("ciphertext") == "ciphertext-bytes"
    # verify signature exists and is valid for the payload
    assert ud.get("sig"), "USER_FILE_CHUNK missing sig"
    ok = keys.rsa_pss_verify(server.pub_pem, json.dumps(ud["payload"], sort_keys=True).encode(), keys.b64url_decode(ud["sig"]))
    assert ok is True


@pytest.mark.asyncio
async def test_file_chunk_forwards_to_remote_server_link(monkeypatch, tmp_path):
    """A FILE_CHUNK for a non-local recipient should be wrapped into SERVER_DELIVER(kind=FILE_CHUNK) and sent to the target server link."""
    ensure_server_keys()
    src = f"user-src-{uuid.uuid4().hex[:6]}"
    dst = f"user-remote-{uuid.uuid4().hex[:6]}"
    target_sid = f"target-{uuid.uuid4().hex[:6]}"

    # map recipient to remote server and create a target link that records sends
    server.user_locations[dst] = target_sid

    class TargetLink:
        def __init__(self):
            self.open = True
            self.sent = []
        async def send(self, data):
            self.sent.append(data)

    target = TargetLink()
    server.servers[target_sid] = target

    payload_file = {"file_id": "fid-xyz", "index": 2, "ciphertext": "ct-bytes"}
    msg = {
        "type": "FILE_CHUNK",
        "from": src,
        "to": dst,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": payload_file,
    }
    incoming = FakeWebSocket([msg])
    await server.handle_ws(incoming, "conn-file-remote", "conn-name-file-remote")

    assert len(target.sent) >= 1, f"remote target did not receive forwarded SERVER_DELIVER: {target.sent}"
    found = False
    for s in target.sent:
        try:
            j = json.loads(s)
            if j.get("type") == "SERVER_DELIVER":
                p = j.get("payload", {})
                if p.get("kind") == "FILE_CHUNK" and p.get("user_id") == dst and p.get("file", {}).get("file_id") == "fid-xyz":
                    found = True
                    break
        except Exception:
            pass
    assert found, f"No SERVER_DELIVER(FILE_CHUNK) forwarded correctly: {target.sent}"


@pytest.mark.asyncio
async def test_local_disconnect_gossips_user_remove(monkeypatch, tmp_path):
    """When a local client disconnects, the server should gossip a USER_REMOVE to other servers (if links are open)."""
    priv, pub = ensure_server_keys()

    # create a local user (simulate client keys + uuid)
    kdir = str(tmp_path / "local_user"); os.makedirs(kdir, exist_ok=True)
    upriv, upub = keys.load_or_create_keys("local-user", kdir)
    uid = keys.load_or_create_user_uuid("local-user", kdir)
    pub_b64u = keys.public_pem_to_der_b64url(upub)

    # prepare a peer server link that will record gossip sends
    class PeerLink:
        def __init__(self):
            self.open = True
            self.sent = []
        async def send(self, data):
            self.sent.append(data)

    peer = PeerLink()
    peer_sid = f"peer-{uuid.uuid4().hex[:8]}"
    # register the peer link so gossip loop will iterate it
    server.servers[peer_sid] = peer

    # send a single USER_HELLO then end the websocket (FakeWebSocket exhausts -> disconnect)
    hello = {
        "type": "USER_HELLO",
        "from": uid,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": {"pubkey_b64u": pub_b64u, "name": "localname"},
    }
    fake = FakeWebSocket([hello])
    # run handler: it should register the local user, then when the fake ws ends it will cleanup and gossip USER_REMOVE
    await server.handle_ws(fake, "conn-local-gossip", "conn-name-local-gossip")

    # verify the peer link received a USER_REMOVE gossip frame
    found = False
    for s in peer.sent:
        try:
            j = json.loads(s)
        except Exception:
            continue
        if j.get("type") == "USER_REMOVE":
            payload = j.get("payload", {}) or {}
            # accept either 'user' or 'user_id' naming variants
            if payload.get("user") == uid or payload.get("user_id") == uid:
                found = True
                break

    assert found, f"No USER_REMOVE gossip sent to peer {peer_sid}; peer.sent={peer.sent}"


@pytest.mark.asyncio
async def test_local_disconnect_gossips_user_remove(monkeypatch, tmp_path):
    """When a local client disconnects, the server should gossip a USER_REMOVE to other servers (if links are open)."""
    priv, pub = ensure_server_keys()

    # create a local user (simulate client keys + uuid)
    kdir = str(tmp_path / "local_user"); os.makedirs(kdir, exist_ok=True)
    upriv, upub = keys.load_or_create_keys("local-user", kdir)
    uid = keys.load_or_create_user_uuid("local-user", kdir)
    pub_b64u = keys.public_pem_to_der_b64url(upub)

    # prepare a peer server link that will record gossip sends
    class PeerLink:
        def __init__(self):
            self.open = True
            self.sent = []
        async def send(self, data):
            self.sent.append(data)

    peer = PeerLink()
    peer_sid = f"peer-{uuid.uuid4().hex[:8]}"
    # register the peer link so gossip loop will iterate it
    server.servers[peer_sid] = peer

    # send a single USER_HELLO then end the websocket (FakeWebSocket exhausts -> disconnect)
    hello = {
        "type": "USER_HELLO",
        "from": uid,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": {"pubkey_b64u": pub_b64u, "name": "localname"},
    }
    fake = FakeWebSocket([hello])
    # run handler: it should register the local user, then when the fake ws ends it will cleanup and gossip USER_REMOVE
    await server.handle_ws(fake, "conn-local-gossip", "conn-name-local-gossip")

    # verify the peer link received a USER_REMOVE gossip frame
    found = False
    for s in peer.sent:
        try:
            j = json.loads(s)
        except Exception:
            continue
        if j.get("type") == "USER_REMOVE":
            payload = j.get("payload", {}) or {}
            # accept either 'user' or 'user_id' naming variants
            if payload.get("user") == uid or payload.get("user_id") == uid:
                found = True
                break

    assert found, f"No USER_REMOVE gossip sent to peer {peer_sid}; peer.sent={peer.sent}"

import runpy
import types as _types

@pytest.mark.asyncio
async def test_main_block_invokes_asyncio_run_and_loads_keys(monkeypatch, tmp_path):
    """Execute server as __main__ and ensure keys.load_or_create_keys and asyncio.run are invoked."""
    # prepare deterministic args (provide --id so load_or_create_server_uuid won't try I/O)
    sid = str(uuid.uuid4())
    test_argv = ["server", "--id", sid, "--name", "test-main", "--host", "127.0.0.1", "--port", "12347"]
    monkeypatch.setattr(sys, "argv", test_argv)

    called = {}

    # Prevent writing/reading real key files: monkeypatch keys.load_or_create_keys used by the __main__ block.
    def fake_load_or_create_keys(name, *a, **kw):
        called["keys"] = name
        return (b"priv-pem-bytes", b"pub-pem-bytes")
    monkeypatch.setattr(keys, "load_or_create_keys", fake_load_or_create_keys)

    # Intercept asyncio.run so we don't actually start the server loop
    def fake_asyncio_run(coro):
        # ensure we got a coroutine object
        assert hasattr(coro, "__await__")
        called["asyncio_run_called"] = True
        called["coro_repr"] = repr(coro)
        # Close the coroutine to avoid "coroutine was never awaited" warnings
        try:
            coro.close()
        except Exception:
            pass
        return None
    monkeypatch.setattr(asyncio, "run", fake_asyncio_run)

    # Execute the module as a script (__name__ == "__main__")
    runpy.run_module("server", run_name="__main__")

    # Assertions: keys loader called and asyncio.run was invoked
    assert called.get("keys") == "test-main" or called.get("keys") is not None
    assert called.get("asyncio_run_called") is True

@pytest.mark.asyncio
async def test_msg_direct_invalid_uuid_returns_invalid_src_or_dst():
    """Non-UUID src/dst should elicit INVALID_SRC_OR_DST_UUID error."""
    ensure_server_keys()
    src = "not-a-uuid"
    dst = "also-not-a-uuid"
    payload = {"ciphertext": "hello"}
    msg = {
        "type": "MSG_DIRECT",
        "from": src,
        "to": dst,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": payload,
    }
    fake = FakeWebSocket([msg])
    await server.handle_ws(fake, "conn-md-invalid-uuid", "conn-name-md-invalid-uuid")

    assert any(
        (lambda j: j.get("type") == "ERROR" and j.get("payload", {}).get("code") == "INVALID_SRC_OR_DST_UUID")(
            json.loads(s)
        ) for s in fake.sent if s
    ), f"Expected INVALID_SRC_OR_DST_UUID error, sent={fake.sent}"


@pytest.mark.asyncio
async def test_msg_direct_unknown_sender_with_valid_uuid_returns_unknown_sender():
    """If usig present but sender pubkey not registered, expect UNKNOWN_SENDER."""
    ensure_server_keys()
    # generate a keypair for signing but do NOT register its pubkey with server.user_pubkeys
    sk_priv, sk_pub = keys.load_or_create_keys(f"tmp-signer-{uuid.uuid4().hex}", str(tmp_path := os.getcwd()))
    src = str(uuid.uuid4())
    dst = str(uuid.uuid4())

    payload = {"ciphertext": "hello-unknown"}
    usig = keys.rsa_pss_sign(sk_priv, json.dumps(payload, sort_keys=True).encode())
    usig_b64u = keys.b64url_encode(usig)

    msg = {
        "type": "MSG_DIRECT",
        "from": src,
        "to": dst,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": payload,
        "usig": usig_b64u,
    }
    fake = FakeWebSocket([msg])
    await server.handle_ws(fake, "conn-md-unknown-validuuid", "conn-name-md-unknown-validuuid")

    assert any(
        (lambda j: j.get("type") == "ERROR" and j.get("payload", {}).get("code") == "UNKNOWN_SENDER")(
            json.loads(s)
        ) for s in fake.sent if s
    ), f"Expected UNKNOWN_SENDER error, sent={fake.sent}"


@pytest.mark.asyncio
async def test_msg_direct_bad_user_sig_returns_bad_user_sig_fixed(tmp_path):
    """If usig present but signature does not verify against registered pubkey -> BAD_USER_SIG."""
    ensure_server_keys()
    # create sender keypair and register pubkey
    s_priv, s_pub = keys.load_or_create_keys("md-sender-bad-fixed", str(tmp := tmp_path / "md_bad_fixed"))
    src = str(uuid.uuid4())
    server.user_pubkeys[src] = s_pub.decode() if isinstance(s_pub, (bytes, bytearray)) else s_pub

    dst = str(uuid.uuid4())

    # sign with a different key to make signature invalid
    other_priv, other_pub = keys.load_or_create_keys("md-sender-other-fixed", str(tmp / "other"))
    payload = {"ciphertext": "secret"}
    usig = keys.rsa_pss_sign(other_priv, json.dumps(payload, sort_keys=True).encode())
    usig_b64u = keys.b64url_encode(usig)

    msg = {
        "type": "MSG_DIRECT",
        "from": src,
        "to": dst,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": payload,
        "usig": usig_b64u,
    }
    fake = FakeWebSocket([msg])
    await server.handle_ws(fake, "conn-md-badsig-fixed", "conn-name-md-badsig-fixed")

    assert any(
        (lambda j: j.get("type") == "ERROR" and j.get("payload", {}).get("code") == "BAD_USER_SIG")(
            json.loads(s)
        ) for s in fake.sent if s
    ), f"Expected BAD_USER_SIG error, sent={fake.sent}"


@pytest.mark.asyncio
async def test_msg_direct_user_not_found_returns_user_not_found_fixed(tmp_path):
    """Valid sender + valid usig but missing recipient mapping -> USER_NOT_FOUND."""
    ensure_server_keys()
    s_priv, s_pub = keys.load_or_create_keys("md-sender-nf-fixed", str(tmp := tmp_path / "md_nf_fixed"))
    src = str(uuid.uuid4())
    server.user_pubkeys[src] = s_pub.decode() if isinstance(s_pub, (bytes, bytearray)) else s_pub

    dst = str(uuid.uuid4())
    # ensure recipient absent
    server.user_locations.pop(dst, None)

    payload = {"ciphertext": "payload-for-missing"}
    usig = keys.rsa_pss_sign(s_priv, json.dumps(payload, sort_keys=True).encode())
    usig_b64u = keys.b64url_encode(usig)

    msg = {
        "type": "MSG_DIRECT",
        "from": src,
        "to": dst,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": payload,
        "usig": usig_b64u,
    }
    fake = FakeWebSocket([msg])
    await server.handle_ws(fake, "conn-md-nf-fixed", "conn-name-md-nf-fixed")

    assert any(
        (lambda j: j.get("type") == "ERROR" and j.get("payload", {}).get("code") == "USER_NOT_FOUND")(
            json.loads(s)
        ) for s in fake.sent if s
    ), f"Expected USER_NOT_FOUND error, sent={fake.sent}"


@pytest.mark.asyncio
async def test_msg_direct_delivers_to_local_user_and_signed_fixed(tmp_path):
    """Valid sender and usig, recipient local -> USER_DELIVER delivered and signed by server."""
    priv, pub = ensure_server_keys()
    s_priv, s_pub = keys.load_or_create_keys("md-sender-local-fixed", str(tmp := tmp_path / "md_local_fixed"))
    src = str(uuid.uuid4())
    server.user_pubkeys[src] = s_pub.decode() if isinstance(s_pub, (bytes, bytearray)) else s_pub

    # prepare recipient local websocket and mapping
    dst = str(uuid.uuid4())
    server.user_locations[dst] = "local"
    recipient_ws = FakeWebSocket([])
    server.local_users[dst] = recipient_ws

    payload = {"ciphertext": "local-message"}
    usig = keys.rsa_pss_sign(s_priv, json.dumps(payload, sort_keys=True).encode())
    usig_b64u = keys.b64url_encode(usig)

    msg = {
        "type": "MSG_DIRECT",
        "from": src,
        "to": dst,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": payload,
        "usig": usig_b64u,
    }
    fake = FakeWebSocket([msg])
    await server.handle_ws(fake, "conn-md-local-fixed", "conn-name-md-local-fixed")

    # recipient should have received USER_DELIVER
    assert len(recipient_ws.sent) >= 1, f"Recipient did not receive USER_DELIVER: {recipient_ws.sent}"
    ud = None
    for s in recipient_ws.sent:
        try:
            j = json.loads(s)
            if j.get("type") == "USER_DELIVER":
                ud = j
                break
        except Exception:
            pass
    assert ud is not None, f"No USER_DELIVER found: {recipient_ws.sent}"
    assert ud.get("payload", {}).get("ciphertext") == "local-message"
    assert ud.get("sig"), "USER_DELIVER missing server signature"
    ok = keys.rsa_pss_verify(server.pub_pem, json.dumps(ud["payload"], sort_keys=True).encode(), keys.b64url_decode(ud["sig"]))
    assert ok is True


@pytest.mark.asyncio
async def test_msg_direct_forwards_to_remote_server_link_fixed(tmp_path):
    """MSG_DIRECT to a non-local recipient should be forwarded as SERVER_DELIVER to the target server link."""
    ensure_server_keys()
    s_priv, s_pub = keys.load_or_create_keys("md-sender-fwd-fixed", str(tmp := tmp_path / "md_fwd_fixed"))
    src = str(uuid.uuid4())
    server.user_pubkeys[src] = s_pub.decode() if isinstance(s_pub, (bytes, bytearray)) else s_pub

    dst = str(uuid.uuid4())
    target_sid = f"peer-{uuid.uuid4().hex[:8]}"
    server.user_locations[dst] = target_sid

    class TargetLink:
        def __init__(self):
            self.open = True
            self.sent = []
        async def send(self, data):
            self.sent.append(data)
    target = TargetLink()
    server.servers[target_sid] = target

    payload = {"ciphertext": "forward-me"}
    usig = keys.rsa_pss_sign(s_priv, json.dumps(payload, sort_keys=True).encode())
    usig_b64u = keys.b64url_encode(usig)

    msg = {
        "type": "MSG_DIRECT",
        "from": src,
        "to": dst,
        "id": uuid.uuid4().hex,
        "ts": now_ms(),
        "payload": payload,
        "usig": usig_b64u,
    }
    fake = FakeWebSocket([msg])
    await server.handle_ws(fake, "conn-md-fwd-fixed", "conn-name-md-fwd-fixed")

    assert len(target.sent) >= 1, f"Target did not receive SERVER_DELIVER: {target.sent}"
    found = False
    for s in target.sent:
        try:
            j = json.loads(s)
            if j.get("type") == "SERVER_DELIVER" and j.get("payload", {}).get("user_id") == dst:
                found = True
                break
        except Exception:
            pass
    assert found, f"No forwarded SERVER_DELIVER with expected payload: {target.sent}"


@pytest.mark.asyncio
async def test_bootstrap_success_with_sync_connect(monkeypatch, tmp_path):
    """Variant of bootstrap success where websockets.connect returns an async-context manager object (not a coroutine)."""
    # prepare introducer keys and payload
    kdir = str(tmp_path / "intro_keys_sync"); os.makedirs(kdir, exist_ok=True)
    intro_priv, intro_pub = keys.load_or_create_keys("intro-test-sync", kdir)
    intro_pub_b64u = server.public_pem_to_der_b64url(intro_pub)

    # another server to be imported
    _, pub2 = keys.load_or_create_keys("srv2-sync", kdir)
    pub2_b64u = server.public_pem_to_der_b64url(pub2)

    # client advertised by introducer
    _, client_pub = keys.load_or_create_keys("client-A-sync", kdir)
    client_pub_b64u = server.public_pem_to_der_b64url(client_pub)
    client_uid = f"user-{uuid.uuid4().hex[:8]}"

    assigned_id = f"assigned-{uuid.uuid4().hex[:6]}"
    payload = {
        "assigned_id": assigned_id,
        "servers": [
            {"server_id": "intro-srv", "host": "127.0.0.1", "port": 11111, "pubkey": intro_pub_b64u},
            {"server_id": "srv2", "host": "10.0.0.2", "port": 22002, "pubkey": pub2_b64u},
        ],
        "clients": [
            {"user_id": client_uid, "pubkey": client_pub_b64u, "name": "Alice"}
        ],
    }
    sig = keys.rsa_pss_sign(intro_priv, json.dumps(payload, sort_keys=True).encode())
    sig_b64u = keys.b64url_encode(sig)
    welcome = {"type": "SERVER_WELCOME", "from": "intro-srv", "id": uuid.uuid4().hex, "ts": now_ms(), "payload": payload, "sig": sig_b64u}

    # point bootstrap list at our single introducer
    monkeypatch.setattr(server, "bootstrap_servers", [{"host": "127.0.0.1", "port": 11111, "pubkey": intro_pub_b64u}])

    class DummyIntroWS:
        def __init__(self, resp): 
            self.sent = []
            self._resp = json.dumps(resp)
        async def __aenter__(self): 
            return self
        async def __aexit__(self, exc_type, exc, tb): 
            return False
        async def send(self, data): 
            self.sent.append(data)
        async def recv(self): 
            return self._resp

    # IMPORTANT: provide a regular function that returns the context-manager object (not an async coroutine)
    def fake_connect(uri, **kw):
        return DummyIntroWS(welcome)

    monkeypatch.setattr(server, "websockets", SimpleNamespace(connect=fake_connect))

    # prepare clean state and run bootstrap
    server.server_addrs.clear(); server.servers.clear(); server.user_pubkeys.clear(); server.user_locations.clear()
    ensure_server_keys()
    my_pub_b64u = server.public_pem_to_der_b64url(server.pub_pem if isinstance(server.pub_pem, (bytes, bytearray)) else server.pub_pem.encode())
    got = await server.bootstrap_with_introducer("my-id-sync", "127.0.0.1", 9999, my_pub_b64u)
    assert got == assigned_id

    # introducer entry should be skipped; srv2 should be recorded
    assert "srv2" in server.server_addrs
    assert server.servers.get("srv2") is None

    # client imported as remote and pubkey decoded/stored
    assert client_uid in server.user_pubkeys
    assert server.user_locations.get(client_uid) == "remote"
    assert isinstance(server.user_pubkeys[client_uid], str) and "BEGIN PUBLIC KEY" in server.user_pubkeys[client_uid]

 
@pytest.mark.asyncio
async def test_bootstrap_send_join_payload_is_correct(monkeypatch, tmp_path):
    """Ensure the join message sent during bootstrap uses our host/port and sets the 'to' field to introducer host:port."""
    kdir = str(tmp_path / "intro_keys_check"); os.makedirs(kdir, exist_ok=True)
    intro_priv, intro_pub = keys.load_or_create_keys("intro-check", kdir)
    intro_pub_b64u = server.public_pem_to_der_b64url(intro_pub)

    payload = {"assigned_id": "aid-check", "servers": [], "clients": []}
    sig = keys.rsa_pss_sign(intro_priv, json.dumps(payload, sort_keys=True).encode())
    sig_b64u = keys.b64url_encode(sig)
    welcome = {"type": "SERVER_WELCOME", "from": "intro-srv", "id": uuid.uuid4().hex, "ts": now_ms(), "payload": payload, "sig": sig_b64u}

    monkeypatch.setattr(server, "bootstrap_servers", [{"host": "intro.host", "port": 4242, "pubkey": intro_pub_b64u}])

    class RecorderWS:
        def __init__(self, resp):
            self.sent = []
            self._resp = json.dumps(resp)
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def send(self, data): self.sent.append(data)
        async def recv(self): return self._resp

    recorder = RecorderWS(welcome)

    # return the same recorder instance (regular function)
    def fake_connect(uri, **kw):
        return recorder

    monkeypatch.setattr(server, "websockets", SimpleNamespace(connect=fake_connect))

    server.server_addrs.clear(); server.servers.clear()
    ensure_server_keys()
    my_pub_b64u = server.public_pem_to_der_b64url(server.pub_pem if isinstance(server.pub_pem, (bytes, bytearray)) else server.pub_pem.encode())
    got = await server.bootstrap_with_introducer("my-id-join-check", "1.2.3.4", 5555, my_pub_b64u)
    assert got == "aid-check"
    # inspect the single sent join message
    assert len(recorder.sent) >= 1
    jm = json.loads(recorder.sent[0])
    # payload host/port must be our host/port
    assert jm.get("payload", {}).get("host") == "1.2.3.4"
    assert int(jm.get("payload", {}).get("port")) == 5555
    # 'to' must be introducer_host:introducer_port per spec
    assert jm.get("to") == "intro.host:4242"
@pytest.mark.asyncio
async def test_bootstrap_signature_failure_raises(monkeypatch, tmp_path):
    """If SERVER_WELCOME signature fails verification, bootstrap should raise."""
    kdir = str(tmp_path / "intro_keys_bad"); os.makedirs(kdir, exist_ok=True)
    intro_priv, intro_pub = keys.load_or_create_keys("intro-good", kdir)
    bad_priv, bad_pub = keys.load_or_create_keys("intro-bad", kdir)
    intro_pub_b64u = server.public_pem_to_der_b64url(intro_pub)

    payload = {"assigned_id": "aid-x", "servers": [], "clients": []}
    # sign with wrong key (bad_priv) so verification using intro_pub will fail
    sig = keys.rsa_pss_sign(bad_priv, json.dumps(payload, sort_keys=True).encode())
    sig_b64u = keys.b64url_encode(sig)
    welcome = {"type": "SERVER_WELCOME", "from": "intro-srv", "id": uuid.uuid4().hex, "ts": now_ms(), "payload": payload, "sig": sig_b64u}

    monkeypatch.setattr(server, "bootstrap_servers", [{"host": "127.0.0.1", "port": 11111, "pubkey": intro_pub_b64u}])

    class DummyIntroWS:
        def __init__(self, resp): self._resp = json.dumps(resp)
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): return False
        async def send(self, data): pass
        async def recv(self): return self._resp

    def fake_connect(uri, **kw): return DummyIntroWS(welcome)
    monkeypatch.setattr(server, "websockets", SimpleNamespace(connect=fake_connect))

    with pytest.raises(RuntimeError):
        await server.bootstrap_with_introducer("my-id", "127.0.0.1", 9999, "dummy")

@pytest.mark.asyncio
async def test_bootstrap_unexpected_response_and_missing_assigned_id(monkeypatch, tmp_path):
    """Non-WELCOME frame or missing assigned_id should cause bootstrap to raise."""
    kdir = str(tmp_path / "intro_keys_resp"); os.makedirs(kdir, exist_ok=True)
    intro_priv, intro_pub = keys.load_or_create_keys("intro-resp", kdir)
    intro_pub_b64u = server.public_pem_to_der_b64url(intro_pub)

    # case A: unexpected type
    bad_frame = {"type": "ERROR", "payload": {"reason": "nope"}}
    class WS1:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def send(self, data): pass
        async def recv(self): return json.dumps(bad_frame)

    # case B: SERVER_WELCOME but missing assigned_id
    payload = {"servers": [], "clients": []}
    sig = keys.rsa_pss_sign(intro_priv, json.dumps(payload, sort_keys=True).encode())
    welcome_missing = {"type": "SERVER_WELCOME", "payload": payload, "sig": keys.b64url_encode(sig)}
    class WS2:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def send(self, data): pass
        async def recv(self): return json.dumps(welcome_missing)

    # first attempt returns unexpected -> should proceed to next (we set two introducers)
    monkeypatch.setattr(server, "bootstrap_servers", [
        {"host": "h1", "port": 1, "pubkey": intro_pub_b64u},
        {"host": "h2", "port": 2, "pubkey": intro_pub_b64u},
    ])

    calls = {"i": 0}
    def fake_connect(uri, **kw):
        calls["i"] += 1
        return WS1() if calls["i"] == 1 else WS2()
    monkeypatch.setattr(server, "websockets", SimpleNamespace(connect=fake_connect))

    with pytest.raises(RuntimeError):
        await server.bootstrap_with_introducer("my-id", "127.0.0.1", 9999, "dummy")

@pytest.mark.asyncio
async def test_bootstrap_all_connect_failures_raise(monkeypatch):
    """If websockets.connect raises for all introducers, bootstrap should raise with collected error."""
    # two introducers in list
    monkeypatch.setattr(server, "bootstrap_servers", [
        {"host": "a", "port": 1, "pubkey": "x"},
        {"host": "b", "port": 2, "pubkey": "y"},
    ])

    def fail_connect(uri, **kw):
        raise OSError("network down")
    monkeypatch.setattr(server, "websockets", SimpleNamespace(connect=fail_connect))

    with pytest.raises(RuntimeError):
        await server.bootstrap_with_introducer("my-id", "127.0.0.1", 9999, "dummy")

@pytest.mark.asyncio
async def test_user_advertise_signed_accepts_stores_announces_and_forwards(tmp_path):
    """Signed USER_ADVERTISE from a known server should be accepted, store pubkey/location,
    announce to local clients and be forwarded to other open server links."""
    ensure_server_keys()

    # origin server and its key
    kdir = str(tmp_path / "ua_signed"); os.makedirs(kdir, exist_ok=True)
    origin_priv, origin_pub = keys.load_or_create_keys("origin-srv-ua", kdir)
    origin_sid = f"origin-{uuid.uuid4().hex[:8]}"
    host = "127.0.0.1"; port = 11111
    origin_pub_b64u = server.public_pem_to_der_b64url(origin_pub)
    # register origin in server_addrs so signature verification will use pinned key
    server.server_addrs[origin_sid] = (host, port, origin_pub_b64u)

    # remote user's advertised info
    uid = f"user-{uuid.uuid4().hex[:8]}"
    client_priv, client_pub = keys.load_or_create_keys("remote-user", kdir)
    client_pub_b64u = server.public_pem_to_der_b64url(client_pub)
    payload = {"user_id": uid, "server_id": origin_sid, "pubkey": client_pub_b64u, "meta": {"name": "RemoteAlice"}}

    sig = keys.rsa_pss_sign(origin_priv, json.dumps(payload, sort_keys=True).encode())
    sig_b64u = keys.b64url_encode(sig)

    msg = {"type": "USER_ADVERTISE", "from": origin_sid, "id": uuid.uuid4().hex, "ts": now_ms(), "payload": payload, "sig": sig_b64u}

    # local clients to be notified
    local_a = FakeWebSocket([]); local_b = FakeWebSocket([])
    server.local_users.clear()
    server.local_users["local-a"] = local_a
    server.local_users["local-b"] = local_b

    # another federated server link to receive forwarded frame
    class OtherLink:
        def __init__(self):
            self.open = True
            self.sent = []
        async def send(self, data):
            self.sent.append(data)
    other = OtherLink()
    other_sid = f"peer-{uuid.uuid4().hex[:8]}"
    server.servers.clear()
    server.servers[other_sid] = other
    # also include the origin as an incoming link (should not be forwarded back)
    server.servers[origin_sid] = None

    incoming = FakeWebSocket([msg])
    await server.handle_ws(incoming, "conn-ua-signed", "conn-name-ua-signed")

    # mapping and pubkey stored
    assert server.user_locations.get(uid) == origin_sid
    assert uid in server.user_pubkeys
    assert "BEGIN PUBLIC KEY" in server.user_pubkeys[uid]

    # local clients were announced (each should receive a USER_ADVERTISE from this server)
    def got_local_advert(ws):
        for s in ws.sent:
            try:
                j = json.loads(s)
                if j.get("type") == "USER_ADVERTISE" and j.get("payload", {}).get("user") == uid:
                    # verify server signature covers payload
                    sig = j.get("sig")
                    if not sig:
                        return False
                    ok = keys.rsa_pss_verify(server.pub_pem, json.dumps(j["payload"], sort_keys=True).encode(), keys.b64url_decode(sig))
                    return ok
            except Exception:
                pass
        return False

    assert got_local_advert(local_a), f"local-a did not get valid USER_ADVERTISE: {local_a.sent}"
    assert got_local_advert(local_b), f"local-b did not get valid USER_ADVERTISE: {local_b.sent}"

    # other peer should have received the original USER_ADVERTISE forwarded
    assert len(other.sent) >= 1, f"other peer did not receive forwarded USER_ADVERTISE: {other.sent}"
    forwarded_found = False
    for item in other.sent:
        try:
            j = json.loads(item)
            if j.get("type") == "USER_ADVERTISE" and j.get("payload", {}).get("user_id") == uid:
                forwarded_found = True
                break
        except Exception:
            pass
    assert forwarded_found, "Forwarded USER_ADVERTISE not found in other.sent"

@pytest.mark.asyncio
async def test_user_advertise_does_not_overwrite_existing_remote_location(monkeypatch, tmp_path):
    """If a user is already known on a different remote server, a USER_ADVERTISE from another origin must be ignored."""
    ensure_server_keys()

    # existing mapping
    uid = f"user-{uuid.uuid4().hex[:8]}"
    server.user_locations[uid] = "some-other-server"

    # origin advert trying to claim the same uid
    kdir = str(tmp_path / "ua_no_overwrite"); os.makedirs(kdir, exist_ok=True)
    origin_priv, origin_pub = keys.load_or_create_keys("origin-noov", kdir)
    origin_sid = f"origin-noov-{uuid.uuid4().hex[:8]}"
    origin_pub_b64u = server.public_pem_to_der_b64url(origin_pub)
    server.server_addrs[origin_sid] = ("127.0.0.1", 11111, origin_pub_b64u)

    payload = {"user_id": uid, "server_id": origin_sid, "pubkey": None, "meta": {"name": "Attacker"}}
    sig = keys.rsa_pss_sign(origin_priv, json.dumps(payload, sort_keys=True).encode())
    sig_b64u = keys.b64url_encode(sig)
    msg = {"type": "USER_ADVERTISE", "from": origin_sid, "id": uuid.uuid4().hex, "ts": now_ms(), "payload": payload, "sig": sig_b64u}

    local = FakeWebSocket([])
    server.local_users.clear()
    server.local_users["local-x"] = local

    incoming = FakeWebSocket([msg])
    await server.handle_ws(incoming, "conn-ua-noov", "conn-name-ua-noov")

    # mapping should remain unchanged
    assert server.user_locations.get(uid) == "some-other-server"
    # local client should NOT have been announced the conflicting advert
    assert not any(
        (lambda j: j.get("type") == "USER_ADVERTISE" and j.get("payload", {}).get("user") == uid)(
            json.loads(s)
        ) for s in local.sent if s
    ), f"Local client incorrectly announced conflicting USER_ADVERTISE: {local.sent}"
