import pytest
import stub_connector  # noqa: F401  registers the "stub" connector
from cyberau_common.secrets import FILTER_HEADERS


@pytest.fixture(scope="session")
def vcr_config():
    return {"filter_headers": list(FILTER_HEADERS)}
