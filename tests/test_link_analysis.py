"""Live RDAP tests for domain_age_days.

These hit rdap.org and require network. Skip cleanly if offline so the suite
remains runnable without internet.
"""

import socket

import pytest

from tfatp.link_analysis import domain_age_days


def _online() -> bool:
    try:
        socket.create_connection(("rdap.org", 443), timeout=3).close()
    except OSError:
        return False
    return True


pytestmark = pytest.mark.skipif(not _online(), reason="network/RDAP unavailable")


@pytest.fixture(autouse=True)
def _clear_cache():
    domain_age_days.cache_clear()
    yield
    domain_age_days.cache_clear()


def test_known_old_domain_resolves():
    # google.com — registered 1997, RDAP at the .com registry is reliable.
    age = domain_age_days("google.com")
    assert age is not None, "RDAP should return a registration date for google.com"
    assert age > 365 * 20, f"google.com should be >20y old, got {age} days"


def test_unknown_domain_returns_none():
    # A reserved/invalid label that cannot be registered.
    assert domain_age_days("nonexistent.invalid") is None


def test_lru_cache_hits_on_repeat_lookup():
    domain_age_days("google.com")
    info_after_first = domain_age_days.cache_info()
    domain_age_days("google.com")
    info_after_second = domain_age_days.cache_info()

    assert info_after_second.hits == info_after_first.hits + 1
    assert info_after_second.misses == info_after_first.misses


def test_transient_failure_is_not_cached(monkeypatch):
    """A None result must NOT poison the cache for subsequent lookups."""
    from tfatp import link_analysis

    calls = {"n": 0}

    def flaky(domain: str):
        calls["n"] += 1
        if calls["n"] == 1:
            return None  # first call: simulated transient failure
        return 4242  # second call: success

    monkeypatch.setattr(link_analysis, "_rdap_age_days", flaky)

    first = domain_age_days("example.test")
    second = domain_age_days("example.test")
    third = domain_age_days("example.test")

    assert first is None
    assert second == 4242, "second lookup should re-fetch and succeed"
    assert third == 4242, "third lookup should now hit the cache"
    assert calls["n"] == 2, "third call must come from cache, not the network"
