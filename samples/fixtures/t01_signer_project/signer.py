"""Release signing helpers."""

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def digest(manifest: bytes) -> str:
    return hashlib.sha256(manifest).hexdigest()


def sign_manifest(private_key, manifest: bytes) -> bytes:
    return private_key.sign(
        manifest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
