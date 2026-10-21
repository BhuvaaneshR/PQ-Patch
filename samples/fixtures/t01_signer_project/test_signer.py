"""Tests for signer.py that hold before AND after the migration.

The first two always run. The round trip runs only once signer.py uses oqs: before the patch there is no
ML-DSA key to sign with, so it skips. After the patch it signs with raw key bytes and checks the signature
with an independent verifier, which fails if the patch assumed a method or type that bytes do not have.
"""

from pathlib import Path

import pytest

import signer


def test_digest_is_stable():
    assert signer.digest(b"release-1.0") == signer.digest(b"release-1.0")
    assert len(signer.digest(b"x")) == 64


def test_module_still_exposes_the_signing_entry_point():
    assert callable(signer.sign_manifest)


def test_signature_round_trips_once_migrated():
    if "oqs" not in Path(signer.__file__).read_text(encoding="utf-8"):
        pytest.skip("signer.py has not been migrated to oqs yet")
    import oqs

    with oqs.Signature("ML-DSA-65") as maker:
        public_key = maker.generate_keypair()
        secret_key = maker.export_secret_key()
    signature = signer.sign_manifest(secret_key, b"release-1.0")
    assert isinstance(signature, bytes) and len(signature) == 3309
    with oqs.Signature("ML-DSA-65") as checker:
        assert checker.verify(b"release-1.0", signature, public_key)
