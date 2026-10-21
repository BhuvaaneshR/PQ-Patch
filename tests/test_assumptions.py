import pytest

from pq_patch.assumptions import Review, review_patch

ORIGINAL = '''"""Signs release manifests."""

from cryptography.hazmat.primitives.asymmetric import padding


def sign_manifest(private_key, manifest: bytes) -> bytes:
    """Return an RSA-PSS signature over the manifest."""
    return private_key.sign(manifest, padding.PSS(mgf=None, salt_length=0), None)
'''

# Exactly what the real model returned on the first live run.
REAL_FIRST_RUN = '''"""Signs release manifests."""

from cryptography.hazmat.primitives.asymmetric import padding
import oqs


def sign_manifest(private_key, manifest: bytes) -> bytes:
    """Return an ML-DSA-65 signature over the manifest."""
    # Assume private_key provides export_secret_key()
    with oqs.Signature('ML-DSA-65', secret_key=private_key.export_secret_key()) as signer:
        return signer.sign(manifest)
'''

CLEAN = '''"""Signs release manifests."""

from cryptography.hazmat.primitives.asymmetric import padding
import oqs


def sign_manifest(private_key, manifest: bytes) -> bytes:
    """Return an ML-DSA-65 signature over the manifest."""
    with oqs.Signature("ML-DSA-65", secret_key=private_key) as signer:
        return signer.sign(manifest)
'''


def test_the_real_first_run_patch_is_flagged_twice():
    r = review_patch(ORIGINAL, REAL_FIRST_RUN)
    assert len(r.problems) == 2 and not r.clean
    assert any("`private_key.export_secret_key`" in p and "never did" in p for p in r.problems)
    assert any("comment on line 9" in p and "Assume" in p for p in r.problems)


def test_a_clean_patch_has_nothing_to_report():
    assert review_patch(ORIGINAL, CLEAN) == Review() and review_patch(ORIGINAL, CLEAN).clean


def test_an_attribute_the_original_already_used_is_not_flagged():
    old = "def f(key, m):\n    return key.sign(m) + key.size\n"
    new = "def f(key, m):\n    return key.sign(m, extra=1) + key.size\n"
    assert review_patch(old, new).problems == ()


def test_a_new_attribute_on_any_kind_of_parameter_is_flagged():
    old = "def f(*args, key, **kw):\n    return key.sign()\n"
    new = "def f(*args, key, **kw):\n    return key.export()\n"
    assert [p.split("`")[3] for p in review_patch(old, new).problems] == ["key.export"]


def test_self_and_cls_are_ignored():
    old = "class A:\n    def f(self, k):\n        return k.sign()\n"
    new = "class A:\n    def f(self, k):\n        return self.helper(k.sign())\n"
    assert review_patch(old, new).problems == ()


def test_a_closure_over_a_parameter_is_covered():
    old = "def f(key):\n    return key.sign()\n"
    new = "def f(key):\n    def inner():\n        return key.export()\n    return inner()\n"
    assert any("key.export" in p for p in review_patch(old, new).problems)


def test_a_function_that_did_not_exist_before_is_not_compared():
    old = "def f(k):\n    return k.sign()\n"
    new = "def f(k):\n    return helper(k)\n\ndef helper(k):\n    return k.anything()\n"
    assert review_patch(old, new).problems == ()


def test_functions_the_patch_did_not_change_are_ignored():
    code = "def g(x):\n    return x.thing()  # assume x is fine\n"
    assert review_patch(code, code).clean


def test_methods_are_compared_by_their_qualified_name():
    old = "class A:\n    def f(self, k):\n        return k.sign()\n\nclass B:\n    def f(self, k):\n        return k.other()\n"
    new = "class A:\n    def f(self, k):\n        return k.sign()\n\nclass B:\n    def f(self, k):\n        return k.brand_new()\n"
    problems = review_patch(old, new).problems
    assert len(problems) == 1 and "`B.f`" in problems[0]


@pytest.mark.parametrize(
    "comment",
    ["assumes the key has a method", "Assuming bytes here", "TODO: check this", "FIXME later", "placeholder until we know"],
)
def test_comments_that_admit_a_guess_or_unfinished_work_are_flagged(comment):
    r = review_patch("x = 1\n", f"x = 1\n# {comment}\n")
    assert len(r.problems) == 1 and "comment on line 2" in r.problems[0]


def test_ordinary_comments_and_unchanged_old_comments_are_not_flagged():
    assert review_patch("x = 1\n", "x = 1\n# the secret key is raw bytes\n").clean
    assert review_patch("x = 1  # assume utf-8\n", "x = 1  # assume utf-8\ny = 2\n").clean  # was already there


def test_a_docstring_that_still_names_the_old_algorithm_is_a_warning_not_a_problem():
    new = CLEAN.replace("Return an ML-DSA-65 signature", "Return an RSA-PSS signature")
    r = review_patch(ORIGINAL, new)
    assert r.problems == () and len(r.warnings) == 1 and "`sign_manifest`" in r.warnings[0]


def test_an_updated_docstring_has_no_warning():
    assert review_patch(ORIGINAL, CLEAN).warnings == ()


def test_a_comment_still_naming_the_old_algorithm_in_a_changed_function_warns():
    old = "def f(k):\n    # RSA-PSS signing\n    return k.sign()\n"
    new = "def f(k):\n    # RSA-PSS signing\n    return sign_bytes(k)\n"
    r = review_patch(old, new)
    assert r.problems == () and any("still names the old algorithm" in w for w in r.warnings)


def test_old_algorithm_wording_in_an_unchanged_function_is_left_alone():
    code = "def g(x):\n    '''RSA helper.'''\n    return x\n\ndef f(k):\n    return k.sign()\n"
    assert review_patch(code, code.replace("k.sign()", "sign_bytes(k)")).warnings == ()


def test_unparseable_input_gives_an_empty_review_not_a_crash():
    assert review_patch("def f(:\n", CLEAN) == Review() and review_patch(ORIGINAL, "def f(:\n") == Review()


def test_a_file_too_deeply_nested_to_analyse_says_so():
    deep = "x = " + "+".join(["1"] * 2000) + "\n"
    r = review_patch(deep, deep + "y = 1\n")
    assert r.problems == ("the static review could not analyse this file: it is nested too deeply",)
