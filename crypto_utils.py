"""
Encryption utilities for the file-sharing service.

Design:
- Every uploaded file gets its OWN random Fernet key ("file key").
- The file is encrypted at rest with that file key (AES-128-CBC + HMAC, via Fernet).
- The file key itself is then encrypted with a "master key" derived from the
  Flask app's SECRET_KEY using PBKDF2-HMAC-SHA256, and only the encrypted
  version of the file key is stored in the database.
- This means a database leak alone does not expose file contents (attacker
  would also need SECRET_KEY), and compromising one file's key does not
  compromise any other file.
"""

import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_master_key(secret_key: str, salt: bytes) -> bytes:
    """Derive a 32-byte urlsafe-base64 Fernet key from the app secret + a salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret_key.encode('utf-8')))


def generate_file_key() -> bytes:
    """Generate a fresh random Fernet key, unique to a single file."""
    return Fernet.generate_key()


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(data)


def decrypt_bytes(token: bytes, key: bytes) -> bytes:
    """Raises cryptography.fernet.InvalidToken if the key/data is wrong or tampered with."""
    return Fernet(key).decrypt(token)
