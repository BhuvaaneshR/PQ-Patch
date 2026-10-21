"""python-rsa calls inside a decorated static method."""

import functools

import rsa


class Notary:
    @staticmethod
    @functools.lru_cache(maxsize=1)
    def fresh_pair():
        return rsa.newkeys(2048)

    @staticmethod
    def seal(message: bytes, private_key) -> bytes:
        return rsa.sign(message, private_key, "SHA-256")
