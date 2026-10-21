"""Check a vendor's RSA PKCS#1 v1.5 signature on a payload."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def is_authentic(public_key, payload: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True
