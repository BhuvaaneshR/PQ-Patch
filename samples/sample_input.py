"""Signs release manifests with a long-lived RSA key."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def sign_manifest(private_key, manifest: bytes) -> bytes:
    """Return an RSA-PSS signature over the manifest."""
    return private_key.sign(
        manifest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
