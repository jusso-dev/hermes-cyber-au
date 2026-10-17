import pytest


@pytest.fixture(autouse=True)
def cyberau_test_env(tmp_path, monkeypatch):
    """Keep connector state in a temporary directory and leave Hindsight off."""
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("HINDSIGHT_BASE_URL", raising=False)
    monkeypatch.delenv("HINDSIGHT_API_KEY", raising=False)
    monkeypatch.delenv("HINDSIGHT_READ_ONLY", raising=False)
    monkeypatch.delenv("CYBERAU_PROFILE_ROLE", raising=False)
    monkeypatch.delenv("HERMES_HOME", raising=False)


@pytest.fixture(scope="session")
def vcr_config():
    return {
        "filter_headers": [
            "authorization",
            "auth-key",
            "x-otx-api-key",
            "x-api-key",
            "api-key",
            "apiKey",
            "apikey",
        ]
    }
