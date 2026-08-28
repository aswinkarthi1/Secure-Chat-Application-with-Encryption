"""
crypto_utils.py
================
All cryptographic primitives for the Secure Chat Application live here.

Design (hybrid encryption, the same pattern TLS/Signal use):
  1. ASYMMETRIC (RSA-2048, OAEP padding)  -> used ONLY to exchange a
     random per-conversation AES session key between two peers.
  2. SYMMETRIC  (AES-256-GCM)             -> used for every actual chat
     message. GCM gives both confidentiality AND integrity (tamper
     detection) via its built-in authentication tag.
  3. PASSWORD HASHING (PBKDF2-HMAC-SHA256, 200k iterations + per-user
     salt) -> used for user authentication, never for message content.

The server NEVER sees a private key, a session key in the clear, or a
plaintext message. It only ever forwards opaque encrypted blobs. That
is what makes this end-to-end (E2E) rather than "encrypted-in-transit".
"""

import os
import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------
# RSA — used only for the key exchange handshake
# ---------------------------------------------------------------------

def generate_rsa_keypair():
    """Generate a fresh RSA-2048 keypair for a client identity."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key) -> str:
    """RSA public key -> base64 PEM string, safe to send over the socket."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(pem).decode()


def deserialize_public_key(b64_pem: str):
    pem = base64.b64decode(b64_pem)
    return serialization.load_pem_public_key(pem)


def serialize_private_key(private_key, password: bytes) -> bytes:
    """Encrypt the private key at rest with the user's password."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )


def deserialize_private_key(pem_bytes: bytes, password: bytes):
    return serialization.load_pem_private_key(pem_bytes, password=password)


def rsa_encrypt(public_key, data: bytes) -> bytes:
    """RSA-OAEP encrypt (used only to wrap a 32-byte AES session key)."""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ---------------------------------------------------------------------
# AES-256-GCM — used for every real chat message
# ---------------------------------------------------------------------

def generate_session_key() -> bytes:
    """32 random bytes = a fresh AES-256 key, one per conversation."""
    return os.urandom(32)


def aes_encrypt(session_key: bytes, plaintext: str) -> dict:
    """
    Encrypt one chat message. A new random 12-byte nonce is used every
    single time (never reuse a nonce with the same key in GCM).
    Returns a JSON-safe dict of base64 strings.
    """
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }


def aes_decrypt(session_key: bytes, payload: dict) -> str:
    aesgcm = AESGCM(session_key)
    nonce = base64.b64decode(payload["nonce"])
    ct = base64.b64decode(payload["ciphertext"])
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt.decode()


def key_fingerprint(session_key: bytes) -> str:
    """Short human-checkable fingerprint, shown in the GUI so users can
    visually confirm both sides derived the same session key (defeats a
    man-in-the-middle who swapped the RSA public keys in transit)."""
    return hashlib.sha256(session_key).hexdigest()[:12].upper()


# ---------------------------------------------------------------------
# Password hashing — for login/authentication, never for messages
# ---------------------------------------------------------------------

def hash_password(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return base64.b64encode(dk).decode(), base64.b64encode(salt).decode()


def verify_password(password: str, stored_hash_b64: str, salt_b64: str) -> bool:
    salt = base64.b64decode(salt_b64)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return base64.b64encode(dk).decode() == stored_hash_b64


# ---------------------------------------------------------------------
# Wire protocol helpers — every socket message is one JSON line
# ---------------------------------------------------------------------

def pack(msg: dict) -> bytes:
    return (json.dumps(msg) + "\n").encode()


def unpack(line: str) -> dict:
    return json.loads(line)
