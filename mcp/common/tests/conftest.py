import pytest
from cyberau_common.secrets import FILTER_HEADERS


@pytest.fixture(scope="session")
def vcr_config():
    return {"filter_headers": list(FILTER_HEADERS)}
