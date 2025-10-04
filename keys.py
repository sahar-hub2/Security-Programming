# keys.py
# Cryptography helpers for SOCP implementation
# - Base64url encode/decode (no padding in JSON)
# - RSA-4096 key management (persist or generate)
# - RSA-OAEP (SHA-256) encryption/decryption
# - RSASSA-PSS (SHA-256) signing/verification

import base64
from pathlib import Path
from typing import Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
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
# RSA key management (4096-bit)
# ----------------------------

def generate_rsa4096() -> Tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
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

def load_or_create_keys(user_id: str, keydir: str = ".keys") -> Tuple[bytes, bytes]:
    """Persist a unique RSA keypair per user; create if missing."""
    p = Path(keydir)
    p.mkdir(parents=True, exist_ok=True)
    priv_path, pub_path = p / f"{user_id}.priv.pem", p / f"{user_id}.pub.pem"
    if priv_path.exists() and pub_path.exists():
        return priv_path.read_bytes(), pub_path.read_bytes()
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
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
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