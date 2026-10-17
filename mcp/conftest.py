import pytest
from cyberau_common.secrets import FILTER_HEADERS, install_cassette_scrubber


@pytest.fixture(scope="session")
def vcr_config():
    return {"filter_headers": list(FILTER_HEADERS)}


def pytest_recording_configure(config, vcr):
    """Post-record scrubber for cassettes opened by pytest-recording."""
    del config
    install_cassette_scrubber(vcr)
