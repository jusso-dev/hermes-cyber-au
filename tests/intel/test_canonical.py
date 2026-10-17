"""Canonical indicator forms and refang property tests."""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from store.canonical import canonical_value, refang

_EXAMPLES = settings(max_examples=25, deadline=None)


def test_defanged_url_matches_plain_url():
    left = canonical_value("url", "hxxps://Example[.]COM/a/../b#x")
    right = canonical_value("url", "https://example.com/b")
    assert left == right == "https://example.com/b"


def test_url_keeps_query_order_and_non_default_port():
    assert (
        canonical_value("url", "https://example.com/b?b=1&a=2#gone")
        == "https://example.com/b?b=1&a=2"
    )
    assert canonical_value("url", "https://example.com:8443/b") == "https://example.com:8443/b"
    assert canonical_value("url", "http://example.com:80/b") == "http://example.com/b"


def test_parenthetical_dot_defang():
    assert canonical_value("url", "hxxps://Example(.)COM/a/../b") == "https://example.com/b"
    assert canonical_value("domain", "Example(.)COM.") == "example.com"


def test_email_lowercases_domain_only():
    assert canonical_value("email", "Analyst[at]Example[.]COM") == "Analyst@example.com"


def test_hashes_are_lowercase_and_length_checked():
    digest = "ab" * 16
    assert canonical_value("md5", digest.upper()) == digest
    with pytest.raises(ValueError):
        canonical_value("sha1", digest)
    with pytest.raises(ValueError):
        canonical_value("sha256", "zz" * 32)


def test_asn_and_cidr():
    assert canonical_value("asn", "as123") == "AS123"
    assert canonical_value("asn", "0") == "AS0"
    with pytest.raises(ValueError):
        canonical_value("asn", "as01")
    with pytest.raises(ValueError):
        canonical_value("asn", "4294967296")
    assert canonical_value("cidr", "192.0.2.1/24") == "192.0.2.0/24"
    assert canonical_value("cidr", "192[.]0[.]2[.]1/24") == "192.0.2.0/24"
    with pytest.raises(ValueError):
        canonical_value("cidr", "192.000.2.0/24")


def test_ipv6_is_compressed_lowercase():
    assert canonical_value("ipv6", "2001:DB8::1") == "2001:db8::1"
    assert canonical_value("ipv6", "[2001:db8::1]") == "2001:db8::1"
    assert canonical_value("ipv6", "2001[:]DB8[:][:]1") == "2001:db8::1"


def test_idna_domain():
    assert canonical_value("domain", "bücher.example.") == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "value",
    ["-bad.com", "bad-.com", "bad..com", "ex ample.com", "example.com/a", ""],
)
def test_invalid_domain(value):
    with pytest.raises(ValueError):
        canonical_value("domain", value)


def test_leading_zero_ipv4_is_rejected():
    with pytest.raises(ValueError):
        canonical_value("ipv4", "192.168.001.1")
    with pytest.raises(ValueError):
        canonical_value("ipv4", "192[.]168[.]001[.]1")
    assert canonical_value("ipv4", "192[.]0[.]2[.]1") == "192.0.2.1"


@_EXAMPLES
@given(st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), max_size=24))
def test_refang_is_idempotent(value):
    once = refang(value)
    assert refang(once) == once


@_EXAMPLES
@given(st.ip_addresses(v=4))
def test_ipv4_defang_round_trip(addr):
    text = str(addr)
    assert canonical_value("ipv4", text) == text
    assert canonical_value("ipv4", text.replace(".", "[.]")) == text
    assert canonical_value("ipv4", text.replace(".", "(.)")) == text


@_EXAMPLES
@given(
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
)
def test_padded_ipv4(a, b, c, d):
    padded = f"{a:03d}.{b:03d}.{c:03d}.{d:03d}"
    if any(len(part) > 1 and part.startswith("0") for part in padded.split(".")):
        with pytest.raises(ValueError):
            canonical_value("ipv4", padded)
    else:
        assert canonical_value("ipv4", padded) == f"{a}.{b}.{c}.{d}"


@_EXAMPLES
@given(st.ip_addresses(v=6))
def test_ipv6_colon_defang(addr):
    text = addr.compressed
    assert canonical_value("ipv6", text.replace(":", "[:]")) == text


@_EXAMPLES
@given(
    st.from_regex(r"[a-z](?:[a-z0-9-]{0,6}[a-z0-9])?", fullmatch=True),
    st.from_regex(r"[a-z]{2,8}", fullmatch=True),
)
def test_domain_defang_and_idempotent(label, tld):
    name = f"{label}.{tld}"
    assert canonical_value("domain", name) == name
    assert canonical_value("domain", name.upper() + ".") == name
    assert canonical_value("domain", name.replace(".", "[.]")) == name
    assert canonical_value("domain", canonical_value("domain", name)) == name


@_EXAMPLES
@given(
    st.sampled_from(["http", "https"]),
    st.from_regex(r"[a-z][a-z0-9]{0,6}", fullmatch=True),
    st.sampled_from(["", "/b", "/a/../b", "/a/./b"]),
    st.sampled_from(["", "?b=1&a=2"]),
)
def test_url_defang_property(scheme, label, path, query):
    host = f"{label}.example"
    plain = f"{scheme}://{host}{path}{query}"
    expected = canonical_value("url", plain)
    defanged = plain.replace("http", "hxxp", 1).replace(".", "[.]") + "#frag"
    assert canonical_value("url", defanged) == expected
    port = 443 if scheme == "https" else 80
    with_port = f"{scheme}://{host}:{port}{path}{query}"
    assert canonical_value("url", with_port) == expected


@_EXAMPLES
@given(st.from_regex(r"[A-Za-z0-9._+-]{1,12}", fullmatch=True))
def test_email_defang_property(local):
    assert canonical_value("email", f"{local}[at]Example(.)COM") == f"{local}@example.com"


@_EXAMPLES
@given(st.binary(min_size=32, max_size=32))
def test_sha256_case(data):
    text = data.hex()
    assert canonical_value("sha256", text.upper()) == text
    assert canonical_value("sha256", text) == text


@_EXAMPLES
@given(st.integers(min_value=0, max_value=4_294_967_295))
def test_asn_property(number):
    assert canonical_value("asn", f"as{number}") == f"AS{number}"
    assert canonical_value("asn", str(number)) == f"AS{number}"


@_EXAMPLES
@given(st.ip_addresses(v=4), st.integers(min_value=0, max_value=32))
def test_cidr_property(addr, prefix):
    network = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
    defanged = str(addr).replace(".", "[.]") + f"/{prefix}"
    assert canonical_value("cidr", defanged) == str(network)


def test_refang_only_touches_a_defanged_scheme():
    assert canonical_value("domain", "hxxpbin.example") == "hxxpbin.example"
    assert canonical_value("domain", "hxxp.example") == "hxxp.example"
    assert canonical_value("url", "http://example.com/?q=hxxp") == "http://example.com/?q=hxxp"
    assert canonical_value("url", "hxxp[:]//example.com/") == "http://example.com/"


def test_url_rfc3986_equivalents_dedupe():
    assert canonical_value("url", "http://example.com") == canonical_value(
        "url", "http://example.com/"
    )
    assert canonical_value("url", "http://example.com/%7e/a%2fb") == canonical_value(
        "url", "http://example.com/~/a%2Fb"
    )


def test_timestamp_overflow_is_a_value_error():
    from store.canonical import canonical_timestamp

    with pytest.raises(ValueError):
        canonical_timestamp("0001-01-01T00:00:00+05:00")
