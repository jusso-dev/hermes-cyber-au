"""Fixtures for the premium contract suite."""

from __future__ import annotations

import pytest
from cyberau_premium.catalog import VendorSpec, bind_vendor, load_vendors


@pytest.fixture(params=load_vendors(), ids=lambda spec: spec.server)
def vendor(request) -> VendorSpec:
    return request.param


@pytest.fixture
def connector(vendor: VendorSpec):
    return bind_vendor(vendor)
