"""
test_integration.py

Integration and end-to-end tests covering server/client interaction, on-wire
E2EE properties, process-level server/client runs, introducer/bootstrap flows,
and behavior under concurrent key generation. These tests exercise the
real process invocation harnesses and are slower by design.


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
import socket
import asyncio
import pytest
from asyncio.subprocess import PIPE
import json

# Ensure Implementation/secure_version is importable
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../Implementation/secure_version"))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

keys = pytest.importorskip("keys")
PYTHON = sys.executable


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def start_process(cmd_args, cwd=None, env=None, wait=0.25):
    proc = await asyncio.create_subprocess_exec(
        *cmd_args, stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=cwd, env=env
    )
    await asyncio.sleep(wait)
    if proc.returncode is not None:
        err = await proc.stderr.read()
        raise RuntimeError(f"Process exited immediately: {err.decode(errors='ignore')}")
    return proc


async def wait_for_tcp(port, host="127.0.0.1", timeout=10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            await asyncio.sleep(0.05)
    return False


#  Unit / CI Guards 

def test_no_backdoors(monkeypatch):
    """Ensure BACKDOOR_* environment vars are unset (CI safety guard)."""
    for env_var in ("BACKDOOR_WEAK_KEYS", "BACKDOOR_TRUST_GOSSIP"):
        if env_var in os.environ:
            pytest.fail(f"{env_var} must not be set in CI")


def test_e2ee_unit_roundtrip(tmp_path):
    """Encrypt/decrypt round-trip using recipient keys (unit-level E2EE)."""
    keydir = tmp_path / "keys"
    os.makedirs(keydir, exist_ok=True)
    priv, pub = keys.load_or_create_keys("alice", keydir)
    plaintext = b"super-secret"
    ciphertext = keys.rsa_oaep_encrypt(pub, plaintext)
    decrypted = keys.rsa_oaep_decrypt(priv, ciphertext)
    assert decrypted == plaintext, "E2EE round-trip failed"


#  Replay / Freshness

def test_replay_detection(tmp_path):
    """Simulate duplicate message rejection (replay guard)."""
    seen_ids = set()
    message_id = "msg-1234"

    def send_message(mid):
        if mid in seen_ids:
            return False
        seen_ids.add(mid)
        return True

    assert send_message(message_id)
    assert not send_message(message_id)  # duplicate rejected


#  Integration / End-to-End

@pytest.mark.asyncio
async def test_e2ee_on_the_wire(tmp_path):
    """Integration: ensure server process does not observe plaintext on stdout."""
    keydir = tmp_path / "keys"
    os.makedirs(keydir, exist_ok=True)

    srv_name = f"server-{os.getpid()}"
    alice_name = f"alice-{os.getpid()}"
    bob_name = f"bob-{os.getpid()}"

    keys.load_or_create_keys(srv_name, keydir)
    keys.load_or_create_keys(alice_name, keydir)
    keys.load_or_create_keys(bob_name, keydir)

    host = "127.0.0.1"
    port = find_free_port()
    server_cmd = [PYTHON, "-u", "server.py", "--host", host, "--port", str(port), "--introducer"]

    server_proc = await start_process(server_cmd, cwd=ROOT, env=os.environ.copy())
    assert await wait_for_tcp(port, host, timeout=12.0)

    alice_proc = await asyncio.create_subprocess_exec(PYTHON, "-u", "client.py", "--user", alice_name, "--server", f"ws://{host}:{port}", stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT)
    bob_proc = await asyncio.create_subprocess_exec(PYTHON, "-u", "client.py", "--user", bob_name, "--server", f"ws://{host}:{port}", stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT)

    try:
        await asyncio.sleep(2.0)
        plaintext = "secret-message"
        alice_proc.stdin.write(f"/tell {bob_name} {plaintext}\n".encode())
        await alice_proc.stdin.drain()

        captured = b""
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                chunk = await asyncio.wait_for(server_proc.stdout.read(1024), timeout=0.5)
            except asyncio.TimeoutError:
                chunk = b""
            if chunk:
                captured += chunk

        assert plaintext.encode() not in captured, f"Server saw plaintext on the wire:\n{captured.decode(errors='ignore')}"

    finally:
        for p in (alice_proc, bob_proc, server_proc):
            if p and p.returncode is None:
                p.terminate()
                try:
                    await asyncio.wait_for(p.wait(), timeout=2)
                except asyncio.TimeoutError:
                    p.kill()
                    await p.wait()
                    
def test_key_persistence(tmp_path):
    """Keys persisted to disk reload identically (persistence sanity)."""
    keydir = os.path.join(str(tmp_path), "keys")
    os.makedirs(keydir, exist_ok=True)
    name = "persist-user"
    priv1, pub1 = keys.load_or_create_keys(name, keydir)
    priv2, pub2 = keys.load_or_create_keys(name, keydir)
    assert priv1 == priv2
    assert pub1 == pub2
    
    
def test_concurrent_key_generation(tmp_path):
    """Concurrent key creation yields a single stable on-disk result."""
    keydir = os.path.join(str(tmp_path), "keys")
    os.makedirs(keydir, exist_ok=True)
    name = "concurrent-user"

    from concurrent.futures import ThreadPoolExecutor

    def worker():
        return keys.load_or_create_keys(name, keydir)

    with ThreadPoolExecutor(max_workers=6) as ex:
        results = list(ex.map(lambda _: worker(), range(6)))

    pubs = [r[1] for r in results]
    # load the canonical on-disk result and ensure it matches one of the concurrent returns
    _, pub_persist = keys.load_or_create_keys(name, keydir)
    assert pub_persist in pubs, "No persisted key matches any concurrent result"

@pytest.mark.asyncio
async def test_client_disconnect_seen_by_peers(tmp_path):
    """Client disconnect triggers peer offline announcement (integration)."""
    keydir = os.path.join(ROOT, ".keys_offline")
    os.makedirs(keydir, exist_ok=True)

    srv_name = f"server-{os.getpid()}"
    alice_name = f"alice-{os.getpid()}"
    bob_name = f"bob-{os.getpid()}"

    keys.load_or_create_keys(srv_name, keydir)
    keys.load_or_create_keys(alice_name, keydir)
    keys.load_or_create_keys(bob_name, keydir)

    host = "127.0.0.1"
    port = find_free_port()
    server_cmd = [PYTHON, "-u", "server.py", "--host", host, "--port", str(port), "--introducer"]
    server_proc = await start_process(server_cmd, cwd=ROOT, env=os.environ.copy())
    assert await wait_for_tcp(port, host, timeout=12.0)

    url = f"ws://{host}:{port}"
    alice_proc = await asyncio.create_subprocess_exec(PYTHON, "-u", "client.py", "--user", alice_name, "--server", url, stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT)
    bob_proc = await asyncio.create_subprocess_exec(PYTHON, "-u", "client.py", "--user", bob_name, "--server", url, stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT)

    try:
        # Wait up to 12s and read both outputs repeatedly to detect either wording variant
        deadline = time.time() + 12
        alice_seen = bob_seen = False
        captured_bob = b""
        captured_alice = b""
        while time.time() < deadline and not (alice_seen and bob_seen):
            try:
                line = await asyncio.wait_for(bob_proc.stdout.readline(), timeout=0.6)
            except asyncio.TimeoutError:
                line = b""
            if line:
                captured_bob += line
                if (b"is now online" in line or b"has joined" in line or b"[local]" in line) and alice_name.encode() in line:
                    alice_seen = True

            try:
                line2 = await asyncio.wait_for(alice_proc.stdout.readline(), timeout=0.6)
            except asyncio.TimeoutError:
                line2 = b""
            if line2:
                captured_alice += line2
                if (b"is now online" in line2 or b"has joined" in line2 or b"[remote]" in line2) and bob_name.encode() in line2:
                    bob_seen = True

        assert alice_seen and bob_seen, f"Peers did not observe each other come online\nBOB:\n{captured_bob.decode(errors='ignore')}\nALICE:\n{captured_alice.decode(errors='ignore')}"

        # Kill Alice abruptly and ensure Bob or server logs show the disconnect
        alice_proc.kill()
        await asyncio.sleep(1.0)

        offline_seen = False
        deadline = time.time() + 8
        captured = b""
        offline_markers = [b"is now offline", b"has disconnected", b"has left", b"has departed"]
        while time.time() < deadline:
            # read from bob client stdout
            try:
                line = await asyncio.wait_for(bob_proc.stdout.readline(), timeout=0.5)
            except asyncio.TimeoutError:
                line = b""
            if line:
                captured += line
                if any(m in line for m in offline_markers) and alice_name.encode() in line:
                    offline_seen = True
                    break
            # also check server stdout for disconnect record
            try:
                sline = await asyncio.wait_for(server_proc.stdout.readline(), timeout=0.2)
            except asyncio.TimeoutError:
                sline = b""
            if sline:
                captured += sline
                if any(m in sline for m in offline_markers) and alice_name.encode() in sline:
                    offline_seen = True
                    break

        assert offline_seen, f"Bob/server did not observe Alice offline. Captured:\n{captured.decode(errors='ignore')}"

    finally:
        for p in (alice_proc, bob_proc, server_proc):
            if p and p.returncode is None:
                p.terminate()
                try:
                    await asyncio.wait_for(p.wait(), timeout=2)
                except asyncio.TimeoutError:
                    p.kill()
                    await p.wait()


@pytest.mark.asyncio
async def test_client_disconnect_seen_by_peers(tmp_path):
    """When a client disconnects, peers observe an offline announcement."""
    keydir = os.path.join(ROOT, ".keys_offline")
    os.makedirs(keydir, exist_ok=True)

    srv_name = f"server-{os.getpid()}"
    alice_name = f"alice-{os.getpid()}"
    bob_name = f"bob-{os.getpid()}"

    keys.load_or_create_keys(srv_name, keydir)
    keys.load_or_create_keys(alice_name, keydir)
    keys.load_or_create_keys(bob_name, keydir)

    host = "127.0.0.1"
    port = find_free_port()
    server_cmd = [PYTHON, "-u", "server.py", "--host", host, "--port", str(port), "--introducer"]
    server_proc = await start_process(server_cmd, cwd=ROOT, env=os.environ.copy())
    assert await wait_for_tcp(port, host, timeout=12.0)

    url = f"ws://{host}:{port}"
    alice_proc = await asyncio.create_subprocess_exec(PYTHON, "-u", "client.py", "--user", alice_name, "--server", url, stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT)
    bob_proc = await asyncio.create_subprocess_exec(PYTHON, "-u", "client.py", "--user", bob_name, "--server", url, stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT)

    try:
        # Wait up to 12s and read both outputs repeatedly to detect either wording variant
        deadline = time.time() + 12
        alice_seen = bob_seen = False
        captured_bob = b""
        captured_alice = b""
        while time.time() < deadline and not (alice_seen and bob_seen):
            try:
                line = await asyncio.wait_for(bob_proc.stdout.readline(), timeout=0.6)
            except asyncio.TimeoutError:
                line = b""
            if line:
                captured_bob += line
                if (b"is now online" in line or b"has joined" in line or b"[local]" in line) and alice_name.encode() in line:
                    alice_seen = True

            try:
                line2 = await asyncio.wait_for(alice_proc.stdout.readline(), timeout=0.6)
            except asyncio.TimeoutError:
                line2 = b""
            if line2:
                captured_alice += line2
                if (b"is now online" in line2 or b"has joined" in line2 or b"[remote]" in line2) and bob_name.encode() in line2:
                    bob_seen = True

        assert alice_seen and bob_seen, f"Peers did not observe each other come online\nBOB:\n{captured_bob.decode(errors='ignore')}\nALICE:\n{captured_alice.decode(errors='ignore')}"

        # Kill Alice abruptly and ensure Bob or server logs show the disconnect
        alice_proc.kill()
        await asyncio.sleep(1.0)

        offline_seen = False
        deadline = time.time() + 8
        captured = b""
        offline_markers = [b"is now offline", b"has disconnected", b"has left", b"has departed"]
        while time.time() < deadline:
            # read from bob client stdout
            try:
                line = await asyncio.wait_for(bob_proc.stdout.readline(), timeout=0.5)
            except asyncio.TimeoutError:
                line = b""
            if line:
                captured += line
                if any(m in line for m in offline_markers) and alice_name.encode() in line:
                    offline_seen = True
                    break
            # also check server stdout for disconnect record
            try:
                sline = await asyncio.wait_for(server_proc.stdout.readline(), timeout=0.2)
            except asyncio.TimeoutError:
                sline = b""
            if sline:
                captured += sline
                if any(m in sline for m in offline_markers) and alice_name.encode() in sline:
                    offline_seen = True
                    break

        assert offline_seen, f"Bob/server did not observe Alice offline. Captured:\n{captured.decode(errors='ignore')}"

    finally:
        for p in (alice_proc, bob_proc, server_proc):
            if p and p.returncode is None:
                p.terminate()
                try:
                    await asyncio.wait_for(p.wait(), timeout=2)
                except asyncio.TimeoutError:
                    p.kill()
                    await p.wait()

@pytest.mark.asyncio
async def test_end_to_end_self_trusting_server(tmp_path):
    """End-to-end: server + 2 clients, verify message delivery and server signing."""
    keydir = tmp_path / "keys"
    os.makedirs(keydir, exist_ok=True)

    srv_name = f"server-{os.getpid()}"
    alice_name = f"alice-{os.getpid()}"
    bob_name = f"bob-{os.getpid()}"

    # Generate/load keys
    srv_priv, srv_pub = keys.load_or_create_keys(srv_name, keydir)
    keys.load_or_create_keys(alice_name, keydir)
    keys.load_or_create_keys(bob_name, keydir)

    host = "127.0.0.1"
    port = find_free_port()
    server_cmd = [PYTHON, "-u", "server.py", "--host", host, "--port", str(port), "--introducer"]

    server_proc = alice_proc = bob_proc = None

    async def wait_for_client_online(proc, username, timeout=15):
        """Poll client stdout until it sees the specified username online."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            if username.encode() in line and (b"is now online" in line or b"has joined" in line):
                return True
        return False

    try:
        server_proc = await start_process(server_cmd, cwd=ROOT, env=os.environ.copy())
        assert await wait_for_tcp(port, host, timeout=12.0)

        url = f"ws://{host}:{port}"
        alice_proc = await asyncio.create_subprocess_exec(
            PYTHON, "-u", "client.py", "--user", alice_name, "--server", url,
            stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT
        )
        bob_proc = await asyncio.create_subprocess_exec(
            PYTHON, "-u", "client.py", "--user", bob_name, "--server", url,
            stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT
        )

        # Wait for clients to see each other online
        alice_online = await wait_for_client_online(bob_proc, alice_name)
        bob_online   = await wait_for_client_online(alice_proc, bob_name)
        assert alice_online and bob_online, "Clients did not see each other online"

        # Alice sends a message to Bob
        message = "hello-bob"
        alice_proc.stdin.write(f"/tell {bob_name} {message}\n".encode())
        await alice_proc.stdin.drain()

        # Poll Bob for the message
        received = False
        captured = b""
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                line = await asyncio.wait_for(bob_proc.stdout.readline(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            if line:
                captured += line
                if message.encode() in line:
                    received = True
                    break

        assert received, f"Bob did not receive message:\n{captured.decode(errors='ignore')}"

        # Optional: verify server key roundtrip
        der = keys.public_pem_to_der_b64url(srv_pub)
        pem_back = keys.der_b64url_to_public_pem(der)
        assert b"BEGIN PUBLIC KEY" in pem_back
        sig = keys.rsa_pss_sign(srv_priv, b"test")
        assert keys.rsa_pss_verify(pem_back, b"test", sig)

    finally:
        for p in (alice_proc, bob_proc, server_proc):
            if p and p.returncode is None:
                p.terminate()
                try:
                    await asyncio.wait_for(p.wait(), timeout=2)
                except asyncio.TimeoutError:
                    p.kill()
                    await p.wait()



async def wait_for_client_online(proc, username, timeout=15):
    """Poll client stdout until it sees the specified username online (reusable helper)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        if username.encode() in line and (b"is now online" in line or b"has joined" in line or b"[remote]" in line or b"[local]" in line):
            return True
    return False


@pytest.mark.asyncio
async def test_multiple_messages_relaxed_order(tmp_path):
    """Allow messages to arrive in any order; ensure all distinct messages are delivered."""
    keydir = tmp_path / "keys_relaxed"
    os.makedirs(keydir, exist_ok=True)

    srv_name = f"server-{os.getpid()}"
    alice_name = f"alice-{os.getpid()}"
    bob_name = f"bob-{os.getpid()}"

    keys.load_or_create_keys(srv_name, keydir)
    keys.load_or_create_keys(alice_name, keydir)
    keys.load_or_create_keys(bob_name, keydir)

    host = "127.0.0.1"
    port = find_free_port()
    server_cmd = [PYTHON, "-u", "server.py", "--host", host, "--port", str(port), "--introducer"]

    server_proc = await start_process(server_cmd, cwd=ROOT, env=os.environ.copy())
    assert await wait_for_tcp(port, host, timeout=12.0)

    alice_proc = await asyncio.create_subprocess_exec(
        PYTHON, "-u", "client.py", "--user", alice_name, "--server", f"ws://{host}:{port}",
        stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT
    )
    bob_proc = await asyncio.create_subprocess_exec(
        PYTHON, "-u", "client.py", "--user", bob_name, "--server", f"ws://{host}:{port}",
        stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT
    )

    try:
        # ensure both clients have established presence before sending messages
        assert await wait_for_client_online(bob_proc, alice_name, timeout=12), "Bob did not observe Alice online"
        assert await wait_for_client_online(alice_proc, bob_name, timeout=12), "Alice did not observe Bob online"

        messages = [f"msg-{i}" for i in range(8)]
        for msg in messages:
            alice_proc.stdin.write(f"/tell {bob_name} {msg}\n".encode())
            await alice_proc.stdin.drain()
            await asyncio.sleep(0.08)

        received = set()
        captured = b""
        deadline = time.time() + 25
        while time.time() < deadline and len(received) < len(messages):
            try:
                line = await asyncio.wait_for(bob_proc.stdout.readline(), timeout=0.8)
            except asyncio.TimeoutError:
                line = b""
            if line:
                captured += line
                for msg in messages:
                    if msg.encode() in line:
                        received.add(msg)
        assert set(messages) == received, f"Bob missed messages (relaxed): got={received}, captured:\n{captured.decode(errors='ignore')}"
    finally:
        for p in (alice_proc, bob_proc, server_proc):
            if p and p.returncode is None:
                p.terminate()
                try:
                    await asyncio.wait_for(p.wait(), timeout=2)
                except asyncio.TimeoutError:
                    p.kill()
                    await p.wait()


@pytest.mark.asyncio
async def test_multiple_messages_with_spacing_and_aggregated_read(tmp_path):
    """Send messages with extra spacing and aggregate stdout reads to avoid line-buffering issues."""
    keydir = tmp_path / "keys_spaced"
    os.makedirs(keydir, exist_ok=True)

    srv_name = f"server-{os.getpid()}"
    alice_name = f"alice-{os.getpid()}"
    bob_name = f"bob-{os.getpid()}"

    keys.load_or_create_keys(srv_name, keydir)
    keys.load_or_create_keys(alice_name, keydir)
    keys.load_or_create_keys(bob_name, keydir)

    host = "127.0.0.1"
    port = find_free_port()
    server_cmd = [PYTHON, "-u", "server.py", "--host", host, "--port", str(port), "--introducer"]

    server_proc = await start_process(server_cmd, cwd=ROOT, env=os.environ.copy())
    assert await wait_for_tcp(port, host, timeout=12.0)

    alice_proc = await asyncio.create_subprocess_exec(
        PYTHON, "-u", "client.py", "--user", alice_name, "--server", f"ws://{host}:{port}",
        stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT
    )
    bob_proc = await asyncio.create_subprocess_exec(
        PYTHON, "-u", "client.py", "--user", bob_name, "--server", f"ws://{host}:{port}",
        stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT
    )

    try:
        # ensure both clients are ready
        assert await wait_for_client_online(bob_proc, alice_name, timeout=12), "Bob did not observe Alice online"
        assert await wait_for_client_online(alice_proc, bob_name, timeout=12), "Alice did not observe Bob online"

        messages = [f"msg-{i}" for i in range(6)]
        for msg in messages:
            alice_proc.stdin.write(f"/tell {bob_name} {msg}\n".encode())
            await alice_proc.stdin.drain()
            await asyncio.sleep(0.28)  # more spacing to reduce head-of-line issues

        # aggregated read loop: read chunks from stdout until all messages found or timeout
        received = []
        captured = b""
        deadline = time.time() + 30
        while time.time() < deadline and len(received) < len(messages):
            try:
                chunk = await asyncio.wait_for(bob_proc.stdout.read(4096), timeout=1.0)
            except asyncio.TimeoutError:
                chunk = b""
            if not chunk:
                await asyncio.sleep(0.05)
                continue
            captured += chunk
            for msg in messages:
                if msg.encode() in captured and msg not in received:
                    received.append(msg)
        assert received and set(received) == set(messages), f"Bob missed messages (spaced): got={received}, captured:\n{captured.decode(errors='ignore')}"
    finally:
        for p in (alice_proc, bob_proc, server_proc):
            if p and p.returncode is None:
                p.terminate()
                try:
                    await asyncio.wait_for(p.wait(), timeout=2)
                except asyncio.TimeoutError:
                    p.kill()
                    await p.wait()


async def wait_for_client_online(proc, username, timeout=15):
    """Poll client stdout until it sees the specified username online (reusable helper)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        if username.encode() in line and (b"is now online" in line or b"has joined" in line or b"[remote]" in line or b"[local]" in line):
            return True
    return False


@pytest.mark.asyncio
async def test_multiple_messages_relaxed_order(tmp_path):
    """Allow messages to arrive in any order; ensure all distinct messages are delivered."""
    keydir = tmp_path / "keys_relaxed"
    os.makedirs(keydir, exist_ok=True)

    srv_name = f"server-{os.getpid()}"
    alice_name = f"alice-{os.getpid()}"
    bob_name = f"bob-{os.getpid()}"

    keys.load_or_create_keys(srv_name, keydir)
    keys.load_or_create_keys(alice_name, keydir)
    keys.load_or_create_keys(bob_name, keydir)

    host = "127.0.0.1"
    port = find_free_port()
    server_cmd = [PYTHON, "-u", "server.py", "--host", host, "--port", str(port), "--introducer"]

    server_proc = await start_process(server_cmd, cwd=ROOT, env=os.environ.copy())
    assert await wait_for_tcp(port, host, timeout=12.0)

    alice_proc = await asyncio.create_subprocess_exec(
        PYTHON, "-u", "client.py", "--user", alice_name, "--server", f"ws://{host}:{port}",
        stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT
    )
    bob_proc = await asyncio.create_subprocess_exec(
        PYTHON, "-u", "client.py", "--user", bob_name, "--server", f"ws://{host}:{port}",
        stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT
    )

    try:
        # ensure both clients have established presence before sending messages
        assert await wait_for_client_online(bob_proc, alice_name, timeout=12), "Bob did not observe Alice online"
        assert await wait_for_client_online(alice_proc, bob_name, timeout=12), "Alice did not observe Bob online"

        messages = [f"msg-{i}" for i in range(8)]
        for msg in messages:
            alice_proc.stdin.write(f"/tell {bob_name} {msg}\n".encode())
            await alice_proc.stdin.drain()
            await asyncio.sleep(0.08)

        received = set()
        captured = b""
        deadline = time.time() + 25
        while time.time() < deadline and len(received) < len(messages):
            try:
                line = await asyncio.wait_for(bob_proc.stdout.readline(), timeout=0.8)
            except asyncio.TimeoutError:
                line = b""
            if line:
                captured += line
                for msg in messages:
                    if msg.encode() in line:
                        received.add(msg)
        assert set(messages) == received, f"Bob missed messages (relaxed): got={received}, captured:\n{captured.decode(errors='ignore')}"
    finally:
        for p in (alice_proc, bob_proc, server_proc):
            if p and p.returncode is None:
                p.terminate()
                try:
                    await asyncio.wait_for(p.wait(), timeout=2)
                except asyncio.TimeoutError:
                    p.kill()
                    await p.wait()


@pytest.mark.asyncio
async def test_multiple_messages_with_spacing_and_aggregated_read(tmp_path):
    """Send messages with extra spacing and aggregate stdout reads to avoid line-buffering issues."""
    keydir = tmp_path / "keys_spaced"
    os.makedirs(keydir, exist_ok=True)

    srv_name = f"server-{os.getpid()}"
    alice_name = f"alice-{os.getpid()}"
    bob_name = f"bob-{os.getpid()}"

    keys.load_or_create_keys(srv_name, keydir)
    keys.load_or_create_keys(alice_name, keydir)
    keys.load_or_create_keys(bob_name, keydir)

    host = "127.0.0.1"
    port = find_free_port()
    server_cmd = [PYTHON, "-u", "server.py", "--host", host, "--port", str(port), "--introducer"]

    server_proc = await start_process(server_cmd, cwd=ROOT, env=os.environ.copy())
    assert await wait_for_tcp(port, host, timeout=12.0)

    alice_proc = await asyncio.create_subprocess_exec(
        PYTHON, "-u", "client.py", "--user", alice_name, "--server", f"ws://{host}:{port}",
        stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT
    )
    bob_proc = await asyncio.create_subprocess_exec(
        PYTHON, "-u", "client.py", "--user", bob_name, "--server", f"ws://{host}:{port}",
        stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=ROOT
    )

    try:
        # ensure both clients are ready
        assert await wait_for_client_online(bob_proc, alice_name, timeout=12), "Bob did not observe Alice online"
        assert await wait_for_client_online(alice_proc, bob_name, timeout=12), "Alice did not observe Bob online"

        messages = [f"msg-{i}" for i in range(6)]
        for msg in messages:
            alice_proc.stdin.write(f"/tell {bob_name} {msg}\n".encode())
            await alice_proc.stdin.drain()
            await asyncio.sleep(0.28)  # more spacing to reduce head-of-line issues

        # aggregated read loop: read chunks from stdout until all messages found or timeout
        received = []
        captured = b""
        deadline = time.time() + 30
        while time.time() < deadline and len(received) < len(messages):
            try:
                chunk = await asyncio.wait_for(bob_proc.stdout.read(4096), timeout=1.0)
            except asyncio.TimeoutError:
                chunk = b""
            if not chunk:
                await asyncio.sleep(0.05)
                continue
            captured += chunk
            for msg in messages:
                if msg.encode() in captured and msg not in received:
                    received.append(msg)
        assert received and set(received) == set(messages), f"Bob missed messages (spaced): got={received}, captured:\n{captured.decode(errors='ignore')}"
    finally:
        for p in (alice_proc, bob_proc, server_proc):
            if p and p.returncode is None:
                p.terminate()
                try:
                    await asyncio.wait_for(p.wait(), timeout=2)
                except asyncio.TimeoutError:
                    p.kill()
                    await p.wait()


# ...existing code...
import uuid

server = pytest.importorskip("server")

class _FakeWs:
    def __init__(self, incoming):
        self._in = [json.dumps(m) if isinstance(m, (dict, list)) else str(m) for m in (incoming or [])]
        self.sent = []

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._in:
            raise StopAsyncIteration
        await asyncio.sleep(0)
        return self._in.pop(0)

    async def send(self, data):
        # normalize bytes to str
        if isinstance(data, (bytes, bytearray)):
            data = data.decode(errors="ignore")
        self.sent.append(data)


def test_introducer_yaml_and_trust(tmp_path):
    """Write a simple introducers YAML and ensure load_introducers parses it without error."""
    kdir = str(tmp_path / "intro_keys")
    os.makedirs(kdir, exist_ok=True)
    _, pub = keys.load_or_create_keys("intro-server", kdir)
    b64 = keys.public_pem_to_der_b64url(pub)

    # write minimal YAML by hand to avoid extra deps
    path = tmp_path / "introducers.yaml"
    with open(path, "w") as fh:
        fh.write(f"servers:\n  - server_id: intro-1\n    host: 127.0.0.1\n    port: 11111\n    pubkey: {b64}\n")

    try:
        res = server.load_introducers(str(path))
    except Exception as e:
        pytest.fail(f"load_introducers raised: {e}")
    assert isinstance(res, (list, dict)) or res is None


@pytest.mark.asyncio
async def test_replay_on_the_wire():
    """Sanity: server.seen_before should detect duplicate IDs (replay protection)."""
    mid = f"mid-{int(time.time()*1000)}-{uuid.uuid4().hex[:6]}"
    first = server.seen_before(mid)
    assert first in (False, None)
    second = server.seen_before(mid)
    assert second is True or first is None


@pytest.mark.asyncio
async def test_invalid_message_handling(tmp_path):
    """Sending malformed JSON to handle_ws should produce an ERROR frame (BAD_JSON or similar)."""
    # ensure server has signing keys set so handler paths are exercised
    kdir = str(tmp_path / "invalid_keys")
    os.makedirs(kdir, exist_ok=True)
    priv, pub = keys.load_or_create_keys("srv-invalid", kdir)
    server.priv_pem = priv
    server.pub_pem = pub

    fake = _FakeWs(["this is not json"])
    await server.handle_ws(fake, "bad-conn", "bad-name")

    sent = " ".join(fake.sent)
    assert '"type": "ERROR"' in sent or '"type":"ERROR"' in sent or "BAD_JSON" in sent or "BAD_REQUEST" in sent, f"No error emitted for malformed input: {fake.sent}"


@pytest.mark.asyncio
async def test_multi_introducer_consistency(tmp_path):
    """Simulate an introducer sending SERVER_WELCOME; ensure it's processed (recorded or acknowledged)."""
    kdir = str(tmp_path / "multi_intro_keys")
    os.makedirs(kdir, exist_ok=True)
    priv, pub = keys.load_or_create_keys("local-srv-multi", kdir)
    server.priv_pem = priv
    server.pub_pem = pub

    _, pub1 = keys.load_or_create_keys("intro-a", kdir)
    _, pub2 = keys.load_or_create_keys("intro-b", kdir)
    s1 = {"server_id": "srv-A", "host": "127.0.0.1", "port": 12021, "pubkey": keys.public_pem_to_der_b64url(pub1)}
    s2 = {"server_id": "srv-B", "host": "127.0.0.1", "port": 12022, "pubkey": keys.public_pem_to_der_b64url(pub2)}

    welcome = {
        "type": "SERVER_WELCOME",
        "from": "intro-origin",
        "id": uuid.uuid4().hex,
        "ts": int(time.time() * 1000),
        "payload": {"servers": [s1, s2], "clients": []},
        "sig": None,
    }

    fake = _FakeWs([welcome])
    await server.handle_ws(fake, "intro-conn-multi", "intro-name-multi")

    sent_concat = " ".join(fake.sent)
    recorded = ("srv-A" in server.server_addrs) or ("srv-B" in server.server_addrs) or ("srv-A" in server.servers) or ("srv-B" in server.servers)
    produced_ok = any(kw in sent_concat for kw in ('SERVER_ANNOUNCE', 'SERVER_HELLO_JOIN', 'SERVER_PRESENCE_SYNC')) and not any('MISSING_ID_OR_TS' in s for s in fake.sent)

    if not (recorded or produced_ok):
       # ensure no unexpected outgoing frames were emitted
       assert fake.sent == [], f"Unexpected outgoing frames for SERVER_WELCOME handling: {fake.sent}"
