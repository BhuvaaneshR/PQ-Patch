"""RSA encryption (OAEP). Out of scope: only signing is migrated, so this is not reported."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def seal(pem: bytes, secret: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(pem)
    return public_key.encrypt(
        secret,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
