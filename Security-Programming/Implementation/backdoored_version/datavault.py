"""
datavault.py
-------------------
Persistent SQLite datastore for SOCP servers.
Implements all mandatory fields from SOCP v1.3 §§13–15.

Tables:
  users(user_id, pubkey, privkey_store, pake_password, meta, version)
  groups(group_id, creator_id, created_at, meta, version)
  group_members(group_id, member_id, role, wrapped_key, added_at)

Each server keeps its own data_vault.sqlite file.

Author: GROUP 12
MEMBERS:  
  1. Debasish Saha Pranta (a1963099, debasishsaha.pranta@student.adelaide.edu.au)
  2. Samin Yeasar Seaum (a1976022, saminyeasar.seaum@student.adelaide.edu.au)
  3. Abidul Kabir (a1974976, abidul.kabir@student.adelaide.edu.au)
  4. Sahar Alzahrani (a1938372, sahar.alzahrani@student.adelaide.edu.au)
  5. Mahrin Mahia (a1957342, mahrin.mahia@student.adelaide.edu.au)
  6. Maria Hasan Logno (a1975478, mariahasan.logno@student.adelaide.edu.au)

"""

import sqlite3, json, time, os, hashlib, base64, asyncio
from typing import Dict, Any

DB_PATH = "data_vault.sqlite"
_LOCK = asyncio.Lock()

# ---------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------
def init_db():
    """Create tables if not already present."""
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.executescript("""
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            pubkey TEXT NOT NULL,
            privkey_store TEXT NOT NULL,
            pake_password TEXT NOT NULL,
            meta TEXT,
            version INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS groups (
            group_id TEXT PRIMARY KEY,
            creator_id TEXT NOT NULL,
            created_at INTEGER,
            meta TEXT,
            version INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS group_members (
            group_id TEXT NOT NULL,
            member_id TEXT NOT NULL,
            role TEXT,
            wrapped_key TEXT NOT NULL,
            added_at INTEGER,
            PRIMARY KEY (group_id, member_id)
        );
        """)
        conn.commit()

# ---------------------------------------------------------------------
# User Management
# ---------------------------------------------------------------------
async def register_user(user_id: str, pubkey_b64u: str,
                        privkey_blob: str, password: str,
                        display_name: str | None = None):
    """Insert or update a user entry."""
    async with _LOCK:
        salt = os.urandom(16)
        hashed = hashlib.sha256(salt + password.encode()).digest()
        pake_verifier = base64.urlsafe_b64encode(salt + hashed).decode()
        meta_json = json.dumps({"display_name": display_name or user_id})
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO users
                (user_id, pubkey, privkey_store, pake_password, meta, version)
                VALUES (?, ?, ?, ?, ?, 1)
            """, (user_id, pubkey_b64u, privkey_blob, pake_verifier, meta_json))
            conn.commit()

async def get_user_pubkey(user_id: str) -> str | None:
    async with _LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.execute("SELECT pubkey FROM users WHERE user_id=?", (user_id,))
            row = cur.fetchone()
            return row[0] if row else None

async def verify_user_password(user_id: str, password: str) -> bool:
    async with _LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.execute("SELECT pake_password FROM users WHERE user_id=?", (user_id,))
            row = cur.fetchone()
            if not row:
                return False
            data = base64.urlsafe_b64decode(row[0].encode())
            salt, stored_hash = data[:16], data[16:]
            return hashlib.sha256(salt + password.encode()).digest() == stored_hash

async def list_users() -> Dict[str, str]:
    """Return {user_id: display_name} for all users."""
    async with _LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.execute("SELECT user_id, meta FROM users")
            result = {}
            for uid, meta_json in cur.fetchall():
                try:
                    dn = json.loads(meta_json).get("display_name", uid)
                except Exception:
                    dn = uid
                result[uid] = dn
            return result

# ---------------------------------------------------------------------
# Public Channel / Groups
# ---------------------------------------------------------------------
async def ensure_public_channel():
    """Create the default 'public' group if missing."""
    async with _LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT OR IGNORE INTO groups
                (group_id, creator_id, created_at, meta, version)
                VALUES ('public', 'system', ?, '{"title":"Public Channel"}', 1)
            """, (int(time.time() * 1000),))
            conn.commit()

async def add_member_to_public(user_id: str, wrapped_key: str):
    """Add a user to the public channel membership list."""
    async with _LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO group_members
                (group_id, member_id, role, wrapped_key, added_at)
                VALUES ('public', ?, 'member', ?, ?)
            """, (user_id, wrapped_key, int(time.time() * 1000)))
            conn.commit()

async def list_public_members() -> Dict[str, Any]:
    """Return {member_id: {...}} for all members of the public channel."""
    async with _LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.execute("""
                SELECT member_id, role, wrapped_key, added_at
                FROM group_members WHERE group_id='public'
            """)
            members = {}
            for mid, role, wkey, ts in cur.fetchall():
                members[mid] = {
                    "member_id": mid,
                    "role": role,
                    "wrapped_key": wkey,
                    "added_at": ts
                }
            return members

# ---------------------------------------------------------------------
# Debug / Dump
# ---------------------------------------------------------------------
async def dump_vault():
    """Print current DB state for debugging."""
    async with _LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            data = {"users": [], "groups": [], "group_members": []}
            for table in data.keys():
                cur = conn.execute(f"SELECT * FROM {table}")
                cols = [c[0] for c in cur.description]
                data[table] = [dict(zip(cols, row)) for row in cur.fetchall()]
            print(json.dumps(data, indent=2))