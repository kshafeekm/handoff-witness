import pytest

import handoff_witness.execution as execution

_real_resolve = execution.resolve_once


@pytest.fixture(autouse=True)
def fixture_invalid_resolves_publicly(monkeypatch):
    """Tests mock the connection for fixture.invalid; give it a global address."""
    def resolve(hostname, port):
        if hostname == "fixture.invalid":
            return ["93.184.216.34"]
        return _real_resolve(hostname, port)
    monkeypatch.setattr(execution, "resolve_once", resolve)
