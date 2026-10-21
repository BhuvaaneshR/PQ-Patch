"""Key agreement with ECDH. Not signing, so a plan must not be made for it."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def agree(peer_public_key):
    private_key = ec.generate_private_key(ec.SECP256R1())
    shared = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"session").derive(shared)
