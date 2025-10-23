'''
keys.py
Cryptography helpers for SOCP implementation
 - Base64url encode/decode (no padding in JSON)
 - RSA-4096 key management (persist or generate)
 - RSA-OAEP (SHA-256) encryption/decryption
 - RSASSA-PSS (SHA-256) signing/verification
 - Public key wire format helpers (DER <-> PEM, base64url)

Author: GROUP 12
MEMBERS:  
  1. Debasish Saha Pranta (a1963099, debasishsaha.pranta@student.adelaide.edu.au)
  2. Samin Yeasar Seaum (a1976022, saminyeasar.seaum@student.adelaide.edu.au)
  3. Abidul Kabir (a1974976, abidul.kabir@student.adelaide.edu.au)
  4. Sahar Alzahrani (a1938372, sahar.alzahrani@student.adelaide.edu.au)
  5. Mahrin Mahia (a1957342, mahrin.mahia@student.adelaide.edu.au)
  6. Maria Hasan Logno (a1975478, mariahasan.logno@student.adelaide.edu.au)
'''
import os
import base64
from pathlib import Path
from typing import Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
    load_der_public_key,
)

# ----------------------------
# Base64url (no padding in JSON)
# ----------------------------

def b64url_encode(data: Union[bytes, bytearray, memoryview]) -> str:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("b64url_encode expects bytes-like input")
    enc = base64.urlsafe_b64encode(bytes(data))
    return enc.rstrip(b"=").decode("ascii")

def b64url_decode(s: Union[str, bytes]) -> bytes:
    if isinstance(s, bytes):
        s = s.decode("ascii")
    if not isinstance(s, str):
        raise TypeError("b64url_decode expects str/bytes input")
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

# ----------------------------
# RSA key generation helpers (backdoor-capable)
# ----------------------------
def _generate_rsa(bits: int) -> Tuple[bytes, bytes]:
    """
    Internal key generator used by both normal and backdoor flows.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem

# ----------------------------
# RSA key management (4096-bit)
# ----------------------------

def generate_rsa4096() -> Tuple[bytes, bytes]:
    """
    Default (secure) key generation entry point. Returns RSA-4096 keypair.
    """
    return _generate_rsa(4096)

def load_or_create_keys(user_id: str, keydir: str = ".keys") -> Tuple[bytes, bytes]:
    """Persist a unique RSA keypair per user; create if missing."""
    p = Path(keydir)
    p.mkdir(parents=True, exist_ok=True)
    priv_path, pub_path = p / f"{user_id}.priv.pem", p / f"{user_id}.pub.pem"
    if priv_path.exists() and pub_path.exists():
        print(f"loaded existing keys")
        return priv_path.read_bytes(), pub_path.read_bytes()
    # Always generate secure RSA-4096 keypairs in secure_version
    priv_pem, pub_pem = generate_rsa4096()
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    return priv_pem, pub_pem

def load_private_pem(pem: bytes):
    return load_pem_private_key(pem, password=None)

def load_public_pem(pem: bytes):
    return load_pem_public_key(pem)

# ----------------------------
# RSA-OAEP (SHA-256) crypto
# ----------------------------

def rsa_oaep_encrypt(pub_pem: bytes, plaintext: bytes) -> bytes:
    pub = load_public_pem(pub_pem)
    return pub.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_oaep_decrypt(priv_pem: bytes, ciphertext: bytes) -> bytes:
    priv = load_private_pem(priv_pem)
    return priv.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

# ----------------------------
# RSASSA-PSS (SHA-256) signatures
# ----------------------------

def rsa_pss_sign(priv_pem: bytes, message: bytes) -> bytes:
    priv = load_private_pem(priv_pem)
    return priv.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

def rsa_pss_verify(pub_pem: bytes, message: bytes, signature: bytes) -> bool:
    pub = load_public_pem(pub_pem)
    try:
        pub.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False

# ----------------------------
# Public key wire format helpers
#   - JSON MUST carry keys as DER base64url (no padding)
#   - Internally we still use PEM for cryptography calls
# ----------------------------

def public_pem_to_der_b64url(pub_pem: bytes) -> str:
    """Convert PEM SubjectPublicKeyInfo -> DER, then base64url (no padding)."""
    pub = load_pem_public_key(pub_pem)
    der = pub.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
    return b64url_encode(der)

def der_b64url_to_public_pem(der_b64u: str) -> bytes:
    """Convert base64url DER SubjectPublicKeyInfo -> PEM bytes."""
    der = b64url_decode(der_b64u)
    pub_obj = load_der_public_key(der)
    # Enforce minimum strength for RSA public keys (reject keys < 2048 bits)
    try:
        if isinstance(pub_obj, RSAPublicKey):
            if getattr(pub_obj, "key_size", 0) < 2048:
                raise ValueError(f"Rejected weak RSA key (size={getattr(pub_obj, 'key_size', 'unknown')})")
    except Exception:
        # If the check fails for any reason, raise to signal invalid/weak key
        raise
    return pub_obj.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)


# ----------------------------
# UUID helpers (persisted)
# ----------------------------
import uuid

def is_uuid_v4(s: str) -> bool:
    try:
        u = uuid.UUID(s, version=4)
        return str(u) == s.lower()
    except Exception:
        return False

def load_or_create_user_uuid(nickname: str, keydir: str = ".keys") -> str:
    """
    Map a human nickname to a stable UUID v4 for on-wire identity.
    Persists mapping at .keys/<nickname>.uuid
    """
    p = Path(keydir)
    p.mkdir(parents=True, exist_ok=True)
    f = p / f"{nickname}.uuid"
    if f.exists():
        return f.read_text().strip()
    new_id = str(uuid.uuid4())
    f.write_text(new_id)
    return new_id

def load_or_create_server_uuid(preferred: str | None = None, keydir: str = ".keys", name: str | None = None) -> str:
    """
    Ensure the server has a stable UUID v4.
    - If 'preferred' is a valid UUID v4, use it and persist.
    - Otherwise create one.
    - If 'name' is given, the UUID is stored at .keys/server_<name>.uuid
    """
    p = Path(keydir)
    p.mkdir(parents=True, exist_ok=True)
    fname = f"server_{name}.uuid" if name else "server.uuid"
    f = p / fname

    if preferred and is_uuid_v4(preferred):
        f.write_text(preferred.lower())
        return preferred.lower()
    if f.exists():
        return f.read_text().strip()

    sid = str(uuid.uuid4())
    f.write_text(sid)
    return sid


if __name__ == "__main__":
    from pathlib import Path
    name = "introducer1"
    priv_pem, pub_pem = load_or_create_keys(name)
    print(f"✅ Created/Loaded: .keys/{name}.priv.pem and .keys/{name}.pub.pem\n")
    print("🔑 Public key (base64url DER):")
    print(public_pem_to_der_b64url(pub_pem))

