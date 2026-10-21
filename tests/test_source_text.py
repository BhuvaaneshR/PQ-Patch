import ast

import pytest

from pq_patch.detector import scan_source
from pq_patch.planner import _scope_text
from pq_patch.source_text import compile_error, import_lines, split_lines, strip_eol


def test_split_lines_keeps_endings_and_round_trips():
    for text in ["", "a", "a\n", "a\nb", "a\r\nb\r\n", "a\rb\r", "a\n\nb\n"]:
        assert "".join(split_lines(text)) == text
    assert split_lines("a\r\nb\rc\nd") == ["a\r\n", "b\r", "c\n", "d"]
    assert split_lines("") == []


@pytest.mark.parametrize("sep", ["\x0c", "\x0b", "\x1c", "\x85", " "])
def test_characters_the_parser_does_not_treat_as_newlines_do_not_split(sep):
    assert split_lines(f"a{sep}b\nc\n") == [f"a{sep}b\n", "c\n"]
    assert len(f"a{sep}b\nc\n".splitlines()) == 3  # str.splitlines would have split here: the bug we avoid


def test_line_numbers_agree_with_the_ast_even_with_a_form_feed():
    source = "x = 1\n\x0c\ndef f():\n    return 2\n"
    func = ast.parse(source).body[1]
    assert strip_eol(split_lines(source)[func.lineno - 1]) == "def f():"
    assert source.splitlines()[func.lineno - 1] != "def f():"  # why str.splitlines is wrong here


def test_planner_shows_the_flagged_line_for_a_file_with_a_form_feed():
    """Regression: str.splitlines() drifted by one line here and hid the flagged call from the model."""
    source = (
        "from cryptography.hazmat.primitives.asymmetric import padding\n\x0c\n\n"
        "def sign(key, m):\n    return key.sign(m, padding.PSS(mgf=None, salt_length=0), None)\n"
    )
    finding = scan_source(source, "t.py").findings[0]
    text, first = _scope_text(finding, [strip_eol(x) for x in split_lines(source)])
    assert first == 4 and text.splitlines()[0] == "def sign(key, m):" and "key.sign" in text


def test_import_lines_lists_all_scopes_and_multiline_imports():
    source = "import os\nfrom a import (\n    b,\n    c,\n)\n\ndef f():\n    import json\n"
    assert import_lines(source) == "import os\nfrom a import (\n    b,\n    c,\n)\n    import json"  # nested one keeps its indent


def test_compile_error_is_none_for_good_code_and_names_the_offending_line():
    assert compile_error("x = 1\n", "t.py") is None
    message = compile_error("x = 1\ny = (2\n", "t.py")
    assert message.startswith("SyntaxError:") and "line 2" in message and "y = (2" in message
    null = compile_error("x = 1\x00", "t.py")  # SyntaxError on Python 3.12, ValueError on older versions
    assert null.startswith(("SyntaxError", "ValueError")) and "null bytes" in null


def test_import_lines_rejects_unparseable_source():
    with pytest.raises(ValueError, match="does not parse"):
        import_lines("def broken(:\n")
