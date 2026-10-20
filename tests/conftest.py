import pytest

import security


@pytest.fixture
def security_events(tmp_path, monkeypatch):
    """Send security events to a temp file and return a function that reads them."""
    path = tmp_path / "security_log.jsonl"
    monkeypatch.setattr(security, "LOG_PATH", path)
    return lambda: security.read_events(path)
