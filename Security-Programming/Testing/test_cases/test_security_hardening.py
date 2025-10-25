import re
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2] / "Implementation" / "secure_version"


def _all_py_files():
    return [p for p in ROOT.rglob("*.py") if "__pycache__" not in p.parts]


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore")


def test_no_backdoor_flags_in_secure_version():
    """Ensure secure_version contains no active BACKDOOR_* config or getenv checks.

    We allow historical mentions in comments, but reject active assignments or os.getenv checks that
    would enable backdoor behaviour at runtime.
    """
    assign_pat = re.compile(r"\bBACKDOOR_[A-Z0-9_]+\s*=")
    getenv_pat = re.compile(r"os\.getenv\([\"']BACKDOOR_[A-Z0-9_]+[\"']")
    found = []
    for p in _all_py_files():
        txt = _read(p)
        if assign_pat.search(txt) or getenv_pat.search(txt):
            found.append(str(p.relative_to(ROOT)))
    assert not found, (
        "Active BACKDOOR flags or getenv usage found in secure_version (should be removed):\n"
        + "\n".join(found)
    )


def test_user_advert_signature_checks_present():
    """Quick static assertions that USER_ADVERTISE handling checks sig and verifies it."""
    server_py = ROOT / "server.py"
    txt = _read(server_py)

    assert "if not sig_b64u or origin_sid not in server_addrs" in txt, "Missing check for missing signature or unknown origin in USER_ADVERTISE"
    assert "rsa_pss_verify(" in txt, "Missing call to rsa_pss_verify for USER_ADVERTISE payloads"


def test_adverts_sent_signed():
    """Ensure the server builds adverts and assigns a signature before sending to clients."""
    server_py = ROOT / "server.py"
    txt = _read(server_py)
    # check for places where advertise messages are signed for local clients
    patterns = [
        'server_advertise["sig"] = sign_payload',
        'advertise_msg["sig"] = sign_payload',
        'local_advert["sig"] = sign_payload',
    ]
    missing = [p for p in patterns if p not in txt]
    assert not missing, f"Expected advert signing assignments not found: {missing}"


def test_der_b64url_to_public_pem_rejects_weak_rsa():
    """Dynamically generate weak (1024-bit) and acceptable (2048-bit) RSA keys and
    verify the public DER->PEM helper enforces minimum RSA key sizes.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from base64 import urlsafe_b64encode

    # import der_b64url_to_public_pem from the secure_version/keys.py by file path
    import importlib.util

    keys_path = ROOT / "keys.py"
    spec = importlib.util.spec_from_file_location("secure_version_keys", str(keys_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    der_b64url_to_public_pem = mod.der_b64url_to_public_pem

    def der_b64url_from_pubkey(pubkey):
        der = pubkey.public_bytes(encoding=serialization.Encoding.DER,
                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
        # base64url no padding
        b64u = urlsafe_b64encode(der).rstrip(b"=")
        return b64u.decode("ascii")

    # weak 1024-bit key should be rejected (ValueError or Exception)
    weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
    weak_der_b64u = der_b64url_from_pubkey(weak_key)
    with pytest.raises(Exception):
        der_b64url_to_public_pem(weak_der_b64u)

    # acceptable 2048-bit key should pass and return PEM bytes
    ok_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    ok_der_b64u = der_b64url_from_pubkey(ok_key)
    pem = der_b64url_to_public_pem(ok_der_b64u)
    assert isinstance(pem, (bytes, bytearray)) and b"BEGIN PUBLIC KEY" in pem


def test_no_literal_weak_key_sizes_in_secure_version():
    """Detect explicit generation of RSA keys with key_size < 2048 in secure_version source files.

    Look for `key_size = N` or `key_size=N` patterns and fail if N < 2048.
    """
    pat = re.compile(r"key_size\s*=\s*(\d+)")
    bad = []
    for p in _all_py_files():
        txt = _read(p)
        for m in pat.finditer(txt):
            try:
                v = int(m.group(1))
            except Exception:
                continue
            if v < 2048:
                bad.append(f"{p.relative_to(ROOT)}: key_size={v}")
    assert not bad, "Found generation of weak RSA keys in secure_version:\n" + "\n".join(bad)


def _load_datavault_module():
    """Load datavault.py from secure_version as a module object."""
    import importlib.util

    dv_path = ROOT / "datavault.py"
    spec = importlib.util.spec_from_file_location("secure_version_datavault", str(dv_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_register_user_resists_sql_injection(tmp_path):
    """Attempt SQL injection via user_id; ensure users table is not dropped and the
    user_id is stored literally.
    """
    import sqlite3
    import asyncio

    dv = _load_datavault_module()

    tmp_db = tmp_path / "test_vault.sqlite"
    # Point datavault DB_PATH at temporary file
    dv.DB_PATH = str(tmp_db)

    # init fresh DB
    dv.init_db()

    malicious_user = "victim'; DROP TABLE users; --"
    # call register_user (async)
    asyncio.run(dv.register_user(malicious_user, "AAA", "priv", "pw", display_name="attacker"))

    # open sqlite and ensure users table exists and the user_id is present literally
    conn = sqlite3.connect(str(tmp_db))
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    assert cur.fetchone() is not None, "users table was dropped (SQL injection succeeded)"

    cur.execute("SELECT user_id, pubkey FROM users WHERE user_id=?", (malicious_user,))
    row = cur.fetchone()
    assert row is not None, "Injected user_id not found as literal; unexpected behavior"
    assert row[0] == malicious_user
    conn.close()


def test_input_length_behavior(tmp_path):
    """Observe how datavault stores very long display names (informational).

    Current behavior: long names are accepted and stored in JSON meta. This test
    records that behaviour so you can decide whether to enforce server-side limits.
    """
    import sqlite3
    import asyncio

    dv = _load_datavault_module()
    tmp_db = tmp_path / "test_vault2.sqlite"
    dv.DB_PATH = str(tmp_db)
    dv.init_db()

    long_name = "A" * 10_000  # large display name
    user_id = "11111111-1111-4111-8111-111111111111"
    asyncio.run(dv.register_user(user_id, "AAA", "priv", "pw", display_name=long_name))

    conn = sqlite3.connect(str(tmp_db))
    cur = conn.cursor()
    cur.execute("SELECT meta FROM users WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    assert row is not None
    meta = row[0]
    assert long_name[:20] in meta
    conn.close()


def test_datavault_sql_parameterization_and_execute_patterns():
    """Heuristic checks that datavault uses parameterized SQL and avoids
    obvious string-formatted SQL in .execute(...) calls.

    This is a lightweight, static heuristic — not a proof, but useful to catch
    accidental string interpolation in SQL statements.
    """
    dv_path = ROOT / "datavault.py"
    txt = _read(dv_path)

    # Ensure common mutating statements use '?' placeholders (parameterized)
    must_have_param = [
        "INSERT OR REPLACE INTO users",
        "INSERT OR IGNORE INTO groups",
        "INSERT OR REPLACE INTO group_members",
    ]
    bad = []
    for stmt in must_have_param:
        # find the occurrence and verify a '?' is present nearby
        idx = txt.find(stmt)
        if idx == -1:
            bad.append(f"Missing expected SQL statement: {stmt}")
            continue
        window = txt[max(0, idx - 200): idx + 400]
        if "?" not in window:
            bad.append(f"Statement '{stmt}' appears without parameter placeholders nearby")

    # Heuristic: detect .execute(f" or .execute("% style calls which may indicate
    # formatted SQL strings. This will flag risky patterns.
    exec_lines = [ln for ln in txt.splitlines() if ".execute(" in ln]
    # flag f-strings or % formatting in execute lines, but ignore the intentional
    # dump_vault() pattern that uses f"SELECT * FROM {table}" over a known-safe list
    exec_risky = []
    for ln in exec_lines:
        if ("f\"" in ln or "f'" in ln or ("%" in ln and "execute(" in ln)):
            if "SELECT * FROM {table}" in ln or "SELECT * FROM {table}" in ln.replace('"', '"'):
                # intentional dump over table names defined in code — skip
                continue
            exec_risky.append(ln)

    assert not bad and not exec_risky, "Datavault SQL parameterization or execute string-formatting issues: \n" + "\n".join(bad + exec_risky)


def test_bandit_scan_no_high_findings(tmp_path):
    """Run bandit on secure_version and fail if any HIGH severity issues are reported.

    Bandit must be installed in the environment; otherwise this test is skipped.
    """
    import shutil
    import subprocess
    import json

    if shutil.which("bandit") is None:
        pytest.skip("bandit not installed in the environment")

    out_json = tmp_path / "bandit_out.json"
    cmd = [
        shutil.which("bandit"),
        "-r",
        str(ROOT),
        "-f",
        "json",
        "-o",
        str(out_json),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    # bandit returns 0 even with findings; parse JSON output
    if not out_json.exists():
        pytest.skip("bandit did not produce JSON output; skipping")

    data = json.loads(out_json.read_text())
    high = [i for i in data.get("results", []) if i.get("issue_severity") == "HIGH"]
    assert not high, f"Bandit reported HIGH severity issues: {json.dumps(high, indent=2)}"
