"""Already signs with ML-DSA through liboqs."""

import oqs


def sign(secret_key: bytes, message: bytes) -> bytes:
    with oqs.Signature("ML-DSA-65", secret_key=secret_key) as signer:
        return signer.sign(message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    with oqs.Signature("ML-DSA-65") as verifier:
        return verifier.verify(message, signature, public_key)
