"""Hashing and message authentication only: nothing here is quantum-vulnerable."""

import hashlib
import hmac


def digest(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def tag(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()
