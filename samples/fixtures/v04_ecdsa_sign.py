"""ECDSA signing with the P-256 curve."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def new_key():
    return ec.generate_private_key(ec.SECP256R1())


def sign(key, data: bytes) -> bytes:
    return key.sign(data, ec.ECDSA(hashes.SHA256()))
