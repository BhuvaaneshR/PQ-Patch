"""Run the detector on real third-party code (pyjwt, trustme).

These need local clones, so they are skipped when the clones are absent:

    git clone --depth 1 https://github.com/jpadilla/pyjwt ../targets/pyjwt
    git clone --depth 1 https://github.com/python-trio/trustme ../targets/trustme

``targets/`` inside this repository (git-ignored) is also accepted.
"""

from pathlib import Path

import pytest

from pq_patch.detector import scan_file, scan_path
from pq_patch.schemas import Algorithm

ROOT = Path(__file__).resolve().parents[1]


def _find(*parts: str) -> Path:
    for base in (ROOT.parent / "targets", ROOT / "targets"):
        candidate = base.joinpath(*parts)
        if candidate.exists():
            return candidate
    pytest.skip(f"clone not found: targets/{'/'.join(parts)}")


def _sites(result):
    return [(f.line, f.original_call, f.algorithm, f.enclosing_scope) for f in result.findings]


def test_pyjwt_algorithms_rsa_and_ecdsa_signing():
    r = scan_file(_find("pyjwt", "jwt", "algorithms.py"))
    assert r.parse_ok
    sites = _sites(r)
    # Line numbers are tied to the cloned revision, so match by (call, scope) instead.
    by_scope = {(call, scope, alg) for _, call, alg, scope in sites}
    assert by_scope == {
        ("key.sign", "RSAAlgorithm.sign", Algorithm.RSA),
        ("key.verify", "RSAAlgorithm.verify", Algorithm.RSA),
        ("ECDSA", "ECAlgorithm.sign", Algorithm.ECDSA),
        ("ECDSA", "ECAlgorithm.verify", Algorithm.ECDSA),
        ("key.sign", "RSAPSSAlgorithm.sign", Algorithm.RSA),
        ("key.verify", "RSAPSSAlgorithm.verify", Algorithm.RSA),
    }
    assert len(sites) == 6


def test_pyjwt_package_parses_and_findings_are_consistent():
    results = scan_path(_find("pyjwt", "jwt"))
    assert results and all(r.parse_ok for r in results)
    for r in results:
        for f in r.findings:  # the Finding validator already enforces range sanity
            assert f.scope_start_line <= f.line <= f.end_line <= f.scope_end_line


def test_trustme_key_generation():
    r = scan_file(_find("trustme", "src", "trustme", "__init__.py"))
    assert r.parse_ok
    assert [(c, a, s) for _, c, a, s in _sites(r)] == [
        ("rsa.generate_private_key", Algorithm.RSA, "KeyType._generate_key"),
        ("ec.generate_private_key", Algorithm.EC, "KeyType._generate_key"),
    ]


def test_trustme_tests_have_no_findings():
    results = scan_path(_find("trustme", "tests"))
    assert results and all(r.parse_ok and not r.findings for r in results)


def test_detector_output_is_deterministic():
    target = _find("pyjwt", "jwt")
    assert scan_path(target) == scan_path(target)
