"""The same RSA calls, reached through import aliases."""

from cryptography.hazmat.primitives import hashes as h
from cryptography.hazmat.primitives.asymmetric import padding as pad
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa


def make_key():
    return _rsa.generate_private_key(public_exponent=65537, key_size=3072)


def endorse(key, text: bytes) -> bytes:
    return key.sign(text, pad.PKCS1v15(), h.SHA256())
