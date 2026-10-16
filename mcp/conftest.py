import pytest


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
