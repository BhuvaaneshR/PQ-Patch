"""A signing key created when the module is imported."""

from cryptography.hazmat.primitives.asymmetric import rsa

SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY = SIGNING_KEY.public_key()
