"""Passes today. It pins an RSA-2048 signature to 256 bytes, so any ML-DSA patch must break it."""

import signer


class FakeRsaKey:
    def sign(self, data, padding, algorithm):
        return b"\x01" * 256


def test_signature_is_256_bytes():
    assert len(signer.sign_manifest(FakeRsaKey(), b"manifest")) == 256
