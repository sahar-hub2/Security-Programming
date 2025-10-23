"""
test_keys.py
---------------
Unit tests for the `keys` helper module.

This file verifies key generation, serialization, RSA-OAEP encryption/decryption,
RSASSA-PSS signing/verification, DER <-> PEM conversions, UUID helpers, and the
gen_introducer_keys utility. It focuses on cryptographic correctness and
persistence behavior for keys used by the secure server/client.

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
import re
from pathlib import Path
import pytest
import importlib.util
import yaml

# Ensure Implementation/secure_version is importable and CWD so keys.py works the same as CLI
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../Implementation/secure_version"))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

keys = pytest.importorskip("keys")

# Verify base64url encoding/decoding roundtrip and that decoding tolerates missing padding
def test_b64url_roundtrip_and_padding():
    b = b"\x00\xffhello\x10"
    s = keys.b64url_encode(b)
    assert isinstance(s, str)
    out = keys.b64url_decode(s)
    assert out == b

    # empty bytes
    s2 = keys.b64url_encode(b"")
    assert keys.b64url_decode(s2) == b""

    # ensure decode tolerates missing padding
    raw = "aGVsbG8"  # "hello" without padding
    assert keys.b64url_decode(raw) == b"hello"


# Ensure keys are generated, persisted to disk, and reloaded identically
def test_generate_and_load_or_create_keys_persistence(tmp_path):
    kd = tmp_path / "kdir"
    kd = str(kd)
    name = f"testuser-{int(time.time()*1000)}"
    priv1, pub1 = keys.load_or_create_keys(name, keydir=kd)
    # files created
    assert Path(kd, f"{name}.priv.pem").exists()
    assert Path(kd, f"{name}.pub.pem").exists()

    # loading again returns identical bytes
    priv2, pub2 = keys.load_or_create_keys(name, keydir=kd)
    assert priv1 == priv2
    assert pub1 == pub2


# Validate that generated RSA keypair uses a 4096-bit private key
def test_generate_rsa4096_key_size():
    priv, pub = keys.generate_rsa4096()
    keyobj = keys.load_private_pem(priv)
    assert getattr(keyobj, "key_size", None) == 4096


# Check RSA-OAEP encryption/decryption roundtrip correctness
def test_rsa_oaep_encrypt_decrypt_roundtrip():
    priv, pub = keys.generate_rsa4096()
    plaintext = b"hello rsa oaep"
    ciphertext = keys.rsa_oaep_encrypt(pub, plaintext)
    assert isinstance(ciphertext, (bytes, bytearray))
    recovered = keys.rsa_oaep_decrypt(priv, ciphertext)
    assert recovered == plaintext


# Test RSASSA-PSS signing and verification and negative cases (tampering)
def test_rsa_pss_sign_verify_and_negative():
    priv, pub = keys.generate_rsa4096()
    msg = b"sign me"
    sig = keys.rsa_pss_sign(priv, msg)
    assert isinstance(sig, (bytes, bytearray))
    assert keys.rsa_pss_verify(pub, msg, sig) is True

    # tamper signature
    bad = bytearray(sig)
    bad[0] ^= 0xFF
    assert keys.rsa_pss_verify(pub, msg, bytes(bad)) is False

    # tamper message
    assert keys.rsa_pss_verify(pub, b"other", sig) is False


# Convert public PEM -> DER+b64url and back, then verify signatures still validate
def test_public_pem_to_der_b64url_and_roundtrip():
    priv, pub = keys.generate_rsa4096()
    der_b64u = keys.public_pem_to_der_b64url(pub)
    assert isinstance(der_b64u, str) and len(der_b64u) > 0
    pem2 = keys.der_b64url_to_public_pem(der_b64u)
    assert isinstance(pem2, (bytes, bytearray))
    # loaded key verifies a signature produced by original private key
    msg = b"roundtrip"
    sig = keys.rsa_pss_sign(priv, msg)
    assert keys.rsa_pss_verify(pem2, msg, sig) is True


# Verify UUID helper persistence and server UUID file behavior
def test_uuid_helpers(tmp_path):
    # user uuid mapping persisted per keydir
    kd = tmp_path / "uuids"
    kd = str(kd)
    nick = "alice-test"
    u1 = keys.load_or_create_user_uuid(nick, keydir=kd)
    assert isinstance(u1, str)
    assert keys.is_uuid_v4(u1) is True

    # reload should return same value
    u2 = keys.load_or_create_user_uuid(nick, keydir=kd)
    assert u1 == u2

    # server uuid preferred behavior and name parameter
    pref = u1.upper()  # test case-insensitive handling for valid v4
    sid = keys.load_or_create_server_uuid(preferred=u1, keydir=kd, name="t1")
    assert sid == u1
    # file stored in lower-case
    assert Path(kd, "server_t1.uuid").read_text().strip() == u1.lower()

    # create new server uuid when none exists (no preferred)
    sid2 = keys.load_or_create_server_uuid(preferred=None, keydir=kd, name="t2")
    assert keys.is_uuid_v4(sid2) is True
    assert Path(kd, "server_t2.uuid").exists()

# Confirm invalid UUIDs are rejected and valid v4 UUIDs are accepted
def test_invalid_uuid_and_is_uuid_v4_behavior():
    # clearly invalid UUIDs should return False
    assert keys.is_uuid_v4("not-a-uuid") is False
    assert keys.is_uuid_v4("1234") is False
    # correct UUID should pass
    assert keys.is_uuid_v4("550e8400-e29b-41d4-a716-446655440000") is True


# Ensure loading malformed PEM data raises an exception
def test_load_private_and_public_pem_with_invalid_data(tmp_path):
    bad_priv = tmp_path / "bad.priv.pem"
    bad_priv.write_text("-----BEGIN PRIVATE KEY-----\nnotkey\n-----END PRIVATE KEY-----")
    with pytest.raises(Exception):
        keys.load_private_pem(bad_priv.read_bytes())

    bad_pub = tmp_path / "bad.pub.pem"
    bad_pub.write_text("-----BEGIN PUBLIC KEY-----\nnotkey\n-----END PUBLIC KEY-----")
    with pytest.raises(Exception):
        keys.load_public_pem(bad_pub.read_bytes())


# Decrypting with the wrong private key should raise an exception
def test_rsa_oaep_decrypt_with_wrong_key_fails():
    priv1, pub1 = keys.generate_rsa4096()
    priv2, pub2 = keys.generate_rsa4096()
    msg = b"top secret"
    cipher = keys.rsa_oaep_encrypt(pub1, msg)
    with pytest.raises(Exception):
        keys.rsa_oaep_decrypt(priv2, cipher)

# rsa_pss_verify should return False (not raise) when given an invalid signature type
def test_rsa_pss_verify_with_invalid_signature_type():
    priv, pub = keys.generate_rsa4096()
    msg = b"verify type"
    # Invalid signature type should not raise, just return False
    result = keys.rsa_pss_verify(pub, msg, "not-bytes-signature")
    assert result is False

# public_pem_to_der_b64url should raise on invalid PEM input
def test_public_pem_to_der_b64url_handles_bad_input():
    with pytest.raises(Exception):
        keys.public_pem_to_der_b64url(b"invalidpem")


# der_b64url_to_public_pem should raise on malformed base64/DER input
def test_der_b64url_to_public_pem_handles_bad_input():
    with pytest.raises(Exception):
        keys.der_b64url_to_public_pem("###invalid###")

# Simulate storage errors when creating server UUID files and ensure errors propagate
def test_generate_and_store_server_uuid_invalid_path(monkeypatch):
    # Simulate directory creation failure cleanly (without touching /root)
    def fake_mkdir(*a, **kw):
        raise PermissionError("cannot create directory")

    monkeypatch.setattr("pathlib.Path.mkdir", fake_mkdir)
    monkeypatch.setattr("builtins.open", lambda *a, **kw: (_ for _ in ()).throw(PermissionError))

    with pytest.raises(PermissionError):
        keys.load_or_create_server_uuid(preferred=None, keydir="/fake/forbidden", name="srv")

# Run gen_introducer_keys.main() and assert keys and introducers.yaml are created
def test_gen_introducer_keys_creates_keys_and_yaml(tmp_path, monkeypatch):
    # Make sure gen_introducer_keys uses tmp_path instead of real filesystem
    intro_file = tmp_path / "introducers.yaml"
    key_dir = tmp_path / ".keys"

    # Import the gen_introducer_keys module dynamically
    spec = importlib.util.spec_from_file_location(
        "gen_introducer_keys",
        str(Path(ROOT, "gen_introducer_keys.py"))
    )
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)

    # Patch constants to redirect paths to tmp_path
    monkeypatch.setattr(gen, "KEYDIR", key_dir)
    monkeypatch.setattr(gen, "YAML_PATH", intro_file)

    # Run main
    gen.main()

    # Check .keys directories and files exist
    for intro in gen.INTRODUCERS:
        priv = key_dir / f"{intro['name']}.priv.pem"
        pub = key_dir / f"{intro['name']}.pub.pem"
        assert priv.exists(), f"Private key missing for {intro['name']}"
        assert pub.exists(), f"Public key missing for {intro['name']}"

    # Check introducers.yaml exists and has correct entries
    assert intro_file.exists()
    data = yaml.safe_load(intro_file.read_text())
    assert isinstance(data, list)
    assert len(data) == len(gen.INTRODUCERS)
    for entry, intro in zip(data, gen.INTRODUCERS):
        assert entry["name"] == intro["name"]
        assert entry["host"] == intro["host"]
        assert entry["port"] == intro["port"]
        assert isinstance(entry["pubkey"], str) and len(entry["pubkey"]) > 0
