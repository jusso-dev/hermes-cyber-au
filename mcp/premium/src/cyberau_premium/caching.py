"""Build an HTTP cache that follows a vendor terms profile."""

from __future__ import annotations

from cyberau_common.cache import HttpCache

from cyberau_premium.base import TermsProfile

_SESSION: list[HttpCache] = []


def cache_for_terms(path, terms: TermsProfile, *, now=None) -> HttpCache:
    ttl_max = terms.cache_ttl_max_s if terms.cache == "ttl" else None
    cache = HttpCache(path, now=now, persistence=terms.cache, ttl_max=ttl_max)
    if terms.cache == "session":
        _SESSION.append(cache)
    return cache


def clear_session_caches() -> None:
    for cache in _SESSION:
        cache.clear_session()
    _SESSION.clear()
