"""Read RSS and Atom feeds the user turned on in watchlists.yaml, read only.

Feeds come from shipped packs (``packs/*.yaml``) and the user's own ``feeds`` list. The
egress policy allows the hosts in the allowlist, which cover the shipped packs, plus the
host of each feed the user configured. A feed URL must be https with a DNS host name, so
the private address floor in the egress policy still applies to every connection.
"""

from __future__ import annotations

import hashlib
import html
import os
import re
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path

from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy, normalise_host
from cyberau_common.envelope import envelope, safe_url, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from cyberau_common.snapshot import unavailable

from .config import ConfigError, Feed, available_packs, load_config

KEY = "custom-feeds"
SERVER = "custom_feeds"
ATTRIBUTION = "Each item is from the feed named in its feed field. Cite that publisher."
MAX_ITEMS = 200
_TTL = 3600
_TRANSPORT = None
_SLEEP = time.sleep
_LIMIT_SLEEP = time.sleep
_CLOCK = time.monotonic
_RETRIES = 1
_TAG = re.compile(r"<[^>]+>")
_SPACE = re.compile(r"\s+")


def custom_feed_list() -> dict:
    """The feeds and watches turned on in watchlists.yaml, and the packs available."""
    try:
        config = load_config()
    except ConfigError as exc:
        return _envelope(None, "snapshot", warnings=(str(exc),))
    data = {
        "packs_enabled": list(config.packs),
        "packs_available": available_packs(),
        "feeds": [
            {"id": feed.id, "label": feed.label, "url": feed.url, "pack": feed.pack}
            for feed in config.feeds
        ],
        "watches": [
            {
                "name": watch.name,
                "title": watch.title,
                "sources": list(watch.sources),
                "lookback_days": watch.lookback_days,
                "pack": watch.pack,
            }
            for watch in config.watches
        ],
    }
    return _envelope(data, "snapshot", warnings=config.warnings)


def custom_feed_items(feed: str, limit: int = 20) -> dict:
    """Recent items from one configured feed, after its category and term filters."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        return _envelope(None, "snapshot", warnings=("limit must be between 1 and 100",))
    try:
        config = load_config()
    except ConfigError as exc:
        return _envelope(None, "snapshot", warnings=(str(exc),))
    chosen = config.feed(str(feed or "").strip())
    if chosen is None:
        return _envelope(None, "snapshot", warnings=("feed is not configured in watchlists.yaml",))
    items, cache, warning = fetch_items(chosen)
    if warning:
        return _envelope(None, cache, warnings=(warning,))
    rows = [present(item) for item in items[:limit]]
    notes = () if rows else ("no items passed this feed's filters",)
    return _envelope(
        {"feed": chosen.id, "label": chosen.label, "items": rows}, cache, warnings=notes
    )


def fetch_items(feed: Feed, *, force_live: bool = False) -> tuple[list[dict], str, str]:
    """Fetch, parse and filter one feed. Items are plain dicts, newest first."""
    text, cache, warning = _fetch(feed, force_live=force_live)
    if text is None:
        return [], cache, warning
    items, problem = parse_feed(text)
    if problem:
        return [], cache, f"{feed.label}: {problem}"
    return filter_items(feed, items), cache, ""


def parse_feed(text: str) -> tuple[list[dict], str | None]:
    """Parse RSS 2.0 or Atom. Refuses a DTD. Returns items with plain text fields."""
    if not text or not text.strip():
        return [], "feed is empty"
    if re.search(r"<!(DOCTYPE|ENTITY)", text[:4096], re.IGNORECASE):
        return [], "feed carries a DTD, refused"
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return [], "feed is not XML"
    tag = _local(root.tag)
    if tag == "rss":
        nodes = [node for node in root.iter() if _local(node.tag) == "item"]
        items = [_rss_item(node) for node in nodes]
    elif tag == "feed":
        nodes = [node for node in root if _local(node.tag) == "entry"]
        items = [_atom_item(node) for node in nodes]
    else:
        return [], "feed is neither RSS nor Atom"
    items = [item for item in items if item["title"] and (item["url"] or item["guid"])]
    for item in items:
        basis = item["guid"] or item["url"] or item["title"]
        item["id"] = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
    items.sort(key=lambda item: item["published"] or "", reverse=True)
    return items, None


def filter_items(feed: Feed, items: list[dict], *, now: datetime | None = None) -> list[dict]:
    """Apply the feed's category, term and age filters, then cap the count."""
    cutoff = (now or datetime.now(UTC)) - timedelta(days=feed.max_age_days)
    wanted = {name.casefold() for name in feed.categories}
    kept = []
    for item in items:
        if item["published"] and item["published"] < cutoff.strftime("%Y-%m-%dT%H:%M:%SZ"):
            continue
        if wanted and not wanted & {name.casefold() for name in item["categories"]}:
            continue
        if feed.include and not has_term(_text(item), feed.include):
            continue
        kept.append(item)
    return kept[:MAX_ITEMS]


def has_term(text: str, terms) -> bool:
    folded = text.casefold()
    return any(_term(term).search(folded) for term in terms)


def present(item: dict) -> dict:
    """An item as a tool returns it: free text wrapped as untrusted."""
    return {
        "id": item["id"],
        "title": untrusted_text(item["title"], KEY, 300),
        "url": item["url"] or None,
        "published": item["published"] or None,
        "categories": [untrusted_text(name, KEY, 80) for name in item["categories"][:10]],
        "summary": untrusted_text(item["summary"], KEY, 600) if item["summary"] else None,
    }


def connector() -> Connector:
    return _FeedsConnector()


class _FeedsConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key=KEY,
            server_name=SERVER,
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "custom_feed_list",
                    "The custom feeds, feed packs and watches turned on in watchlists.yaml.",
                    custom_feed_list,
                ),
                ToolSpec(
                    "custom_feed_items",
                    "Recent items from one configured RSS or Atom feed, by feed id.",
                    custom_feed_items,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        try:
            config = load_config()
        except ConfigError as exc:
            return Probe(self.key, False, str(exc))
        if not live:
            return Probe(self.key, True, f"offline ok, {len(config.feeds)} feeds configured")
        if not config.feeds:
            return Probe(self.key, True, "no feeds configured, no live check was made")
        failed = []
        for feed in config.feeds:
            _items, _cache, warning = fetch_items(feed, force_live=True)
            if warning:
                failed.append(feed.id)
        if failed:
            return Probe(self.key, False, "feeds failed: " + ", ".join(failed))
        return Probe(self.key, True, f"live ok, {len(config.feeds)} feeds")


def _fetch(feed: Feed, *, force_live: bool) -> tuple[str | None, str, str]:
    data_dir = _data_dir()
    cache = HttpCache(data_dir / "http_cache.sqlite")
    cache_key = cache.key("GET", feed.url, None, b"", "anonymous")
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    cached = cache.get(cache_key)
    if cached and not force_live and (offline or cache.fresh(cached)):
        state = "hit" if cache.fresh(cached) else "stale"
        return cached.body.decode("utf-8", "replace"), state, ""
    if offline:
        return None, "snapshot", unavailable(feed.label, "offline mode and no cached copy")
    client = HttpClient(
        KEY,
        policy=_policy(feed),
        cache=cache,
        limiter=RateLimiter(data_dir / "rate_limit.sqlite", clock=_CLOCK, sleeper=_LIMIT_SLEEP),
        user_agent=USER_AGENT,
        rate=1,
        burst=2,
        window="rolling",
        timeout=60,
        retries=_RETRIES,
        transport=_TRANSPORT,
        sleeper=_SLEEP,
    )
    try:
        response = client.get(feed.url, ttl=_TTL, skip_cache=force_live)
    except (HttpError, EgressDenied, TimeoutError) as exc:
        if not force_live and cached:
            return cached.body.decode("utf-8", "replace"), "stale", ""
        return None, "snapshot", unavailable(feed.label, f"the fetch failed ({redact(str(exc))})")
    finally:
        client.close()
    if response.status >= 400:
        return None, response.cache, unavailable(feed.label, f"upstream status {response.status}")
    return response.body.decode("utf-8", "replace"), response.cache, ""


def _policy(feed: Feed) -> EgressPolicy:
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    policy = EgressPolicy(allowlist, KEY)
    # A feed the user configured brings its own host. Shipped packs use allowlisted hosts.
    policy.hosts.add(normalise_host(feed.host))
    return policy


def _rss_item(node: ET.Element) -> dict:
    return {
        "title": _clean(_child_text(node, "title"), 300),
        "url": _https(_child_text(node, "link")),
        "guid": _child_text(node, "guid").strip(),
        "published": _date(_child_text(node, "pubDate") or _child_text(node, "updated")),
        "categories": [
            _clean(child.text or "", 80)
            for child in node
            if _local(child.tag) == "category" and (child.text or "").strip()
        ],
        "summary": _clean(_child_text(node, "description"), 600),
    }


def _atom_item(node: ET.Element) -> dict:
    link = ""
    for child in node:
        if _local(child.tag) == "link" and child.get("rel", "alternate") == "alternate":
            link = child.get("href", "")
            break
    return {
        "title": _clean(_child_text(node, "title"), 300),
        "url": _https(link),
        "guid": _child_text(node, "id").strip(),
        "published": _date(_child_text(node, "published") or _child_text(node, "updated")),
        "categories": [
            _clean(child.get("term", ""), 80)
            for child in node
            if _local(child.tag) == "category" and child.get("term", "").strip()
        ],
        "summary": _clean(_child_text(node, "summary") or _child_text(node, "content"), 600),
    }


def _https(link: str) -> str:
    return safe_url(link.strip(), schemes=("https",)) or ""


def _child_text(node: ET.Element, name: str) -> str:
    for child in node:
        if _local(child.tag) == name:
            return "".join(child.itertext())
    return ""


def _clean(text: str, cap: int) -> str:
    plain = html.unescape(_TAG.sub(" ", html.unescape(text or "")))
    return _SPACE.sub(" ", plain).strip()[:cap]


def _date(text: str) -> str:
    raw = (text or "").strip()
    if not raw:
        return ""
    try:
        moment = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        try:
            moment = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _text(item: dict) -> str:
    return " ".join([item["title"], item["summary"], *item["categories"]])


def _term(term: str) -> re.Pattern:
    return re.compile(r"(?<![0-9a-z])" + re.escape(term.casefold()) + r"(?![0-9a-z])")


def _envelope(data, cache: str, *, warnings=()) -> dict:
    return envelope(KEY, data, cache=cache, warnings=tuple(warnings), attribution=ATTRIBUTION)


def _data_dir() -> Path:
    return Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-custom-feeds"))


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector(KEY, connector)
