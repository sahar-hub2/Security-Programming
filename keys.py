import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding # SCOP 4.Cryptography
from cryptography.hazmat.primitives import hashes, serialization  # SCOP 4.Cryptography
from cryptography.exceptions import InvalidSignature  # SCOP 4.Cryptography
from typing import Tuple

def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def generate_rsa4096() -> Tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv, pub

def load_private_pem(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)

def load_public_pem(pem: bytes):
    return serialization.load_pem_public_key(pem)

def rsa_oaep_encrypt(pub_pem: bytes, plaintext: bytes) -> bytes:
    pub = load_public_pem(pub_pem)
    return pub.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_oaep_decrypt(priv_pem: bytes, ciphertext: bytes) -> bytes:
    priv = load_private_pem(priv_pem)
    return priv.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_pss_sign(priv_pem: bytes, message: bytes) -> bytes:
    priv = load_private_pem(priv_pem)
    return priv.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def rsa_pss_verify(pub_pem: bytes, message: bytes, signature: bytes) -> bool:
    pub = load_public_pem(pub_pem)
    try:
        pub.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
