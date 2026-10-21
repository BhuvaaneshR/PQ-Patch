"""TEST DOUBLE for the liboqs `oqs` package. This is NOT cryptography.

It has the same call shape as liboqs-python's `oqs.Signature` (constructor with an algorithm name and an
optional secret key as bytes, context manager, generate_keypair, export_secret_key, sign, verify) so a
patch that uses the API correctly runs, and a patch that misuses it (a key object where bytes are
expected, a method that does not exist) fails the project's tests. Signatures are an HMAC stretched to the
real ML-DSA-65 size. Never use this for anything but these fixtures. It exists because liboqs is hard to
install on some machines (Windows in particular) and the verifier needs *something* importable as `oqs`.
"""

import hashlib
import hmac
import os

SIGNATURE_SIZES = {"ML-DSA-44": 2420, "ML-DSA-65": 3309, "ML-DSA-87": 4627}


class Signature:
    def __init__(self, alg, secret_key=None):
        if alg not in SIGNATURE_SIZES:
            raise ValueError(f"unsupported mechanism: {alg}")
        if secret_key is not None and not isinstance(secret_key, (bytes, bytearray)):
            raise TypeError("secret_key must be bytes")
        self.alg = alg
        self._secret = bytes(secret_key) if secret_key is not None else None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def _public_from(self, secret):
        return hashlib.sha256(b"public" + secret).digest()

    def generate_keypair(self):
        self._secret = os.urandom(32)
        return self._public_from(self._secret)

    def export_secret_key(self):
        if self._secret is None:
            raise ValueError("no secret key")
        return self._secret

    def sign(self, message):
        if self._secret is None:
            raise ValueError("no secret key")
        tag = hmac.new(self._public_from(self._secret), bytes(message), hashlib.sha256).digest()
        size = SIGNATURE_SIZES[self.alg]
        return (tag * (size // len(tag) + 1))[:size]

    def verify(self, message, signature, public_key):
        tag = hmac.new(bytes(public_key), bytes(message), hashlib.sha256).digest()
        size = SIGNATURE_SIZES[self.alg]
        return hmac.compare_digest((tag * (size // len(tag) + 1))[:size], bytes(signature))
