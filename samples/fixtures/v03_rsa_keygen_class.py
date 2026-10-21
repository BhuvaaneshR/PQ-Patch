"""A small key store that makes an RSA key and signs with it."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class KeyStore:
    def __init__(self):
        self._key = None

    def create(self):
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return self._key.public_key()

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
