"""Feeds and watches from the user's watchlists.yaml and the packs it turns on.

The user file is ``watchlists.yaml`` in the profile data directory, the same file the
watchlist run reads. Three optional keys belong to this module:

```yaml
packs:            # shipped packs to turn on, by name
  - microsoft-security
feeds:            # extra RSS or Atom feeds
  - id: vendor-blog
    label: Vendor security blog
    url: <an https feed URL>
watches:          # daily watches over stored feed items and advisories
  - name: vendor-changes
    title: Vendor security changes
    sources: [vendor-blog]
    any: [security, vulnerability]
```

A pack is a YAML file in ``packs/`` with the same ``feeds`` and ``watches`` keys. A bad
entry is skipped with a warning that names its position, never its value.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

FILE_NAME = "watchlists.yaml"
PACKS_DIR = Path(__file__).resolve().parents[2] / "packs"
_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,40}")
_HOST = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
_MAX_TERMS = 50
_MAX_FEEDS = 50
_MAX_WATCHES = 20


class ConfigError(ValueError):
    """The file is unreadable as a whole."""


@dataclass(frozen=True)
class Feed:
    id: str
    label: str
    url: str
    # Keep only items in one of these feed categories. Empty keeps every item.
    categories: tuple[str, ...] = ()
    # Keep only items whose text has one of these terms. Empty keeps every item.
    include: tuple[str, ...] = ()
    # Ignore items older than this many days, so a long archive feed is not loaded whole.
    max_age_days: int = 14
    pack: str | None = None

    @property
    def host(self) -> str:
        return (urlsplit(self.url).hostname or "").lower()

    @property
    def source_id(self) -> str:
        """The intel store source id for this feed's items."""
        return f"feed-{self.id}"


@dataclass(frozen=True)
class Watch:
    name: str
    title: str
    # Feed ids, or intel store source ids such as auscert or asd-acsc. Empty means all.
    sources: tuple[str, ...] = ()
    any: tuple[str, ...] = ()
    all: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    lookback_days: int = 3
    pack: str | None = None


@dataclass(frozen=True)
class Config:
    feeds: tuple[Feed, ...] = ()
    watches: tuple[Watch, ...] = ()
    packs: tuple[str, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def feed(self, feed_id: str) -> Feed | None:
        return next((item for item in self.feeds if item.id == feed_id), None)


def data_dir() -> Path:
    raw = os.environ.get("CYBERAU_DATA_DIR")
    if raw:
        return Path(raw).expanduser()
    hermes = os.environ.get("HERMES_HOME")
    if hermes:
        return Path(hermes).expanduser() / "plugin-data" / "cyber-au"
    raise ConfigError("set CYBERAU_DATA_DIR or HERMES_HOME")


def config_path(path: str | Path | None = None) -> Path:
    if path is not None and str(path).strip():
        return Path(path).expanduser()
    return data_dir() / FILE_NAME


def packs_dir() -> Path:
    raw = os.environ.get("CYBERAU_WATCH_PACKS_DIR")
    return Path(raw).expanduser() if raw else PACKS_DIR


def available_packs() -> list[str]:
    folder = packs_dir()
    if not folder.is_dir():
        return []
    return sorted(path.stem for path in folder.glob("*.yaml") if _ID.fullmatch(path.stem))


def load_config(path: str | Path | None = None) -> Config:
    """Read feeds and watches. A missing file is an empty config."""
    file = config_path(path)
    if not file.is_file():
        return Config()
    data = _read(file, "watchlist")
    warnings: list[str] = []
    feeds: list[Feed] = []
    watches: list[Watch] = []
    packs: list[str] = []
    raw_packs = data.get("packs")
    if raw_packs is not None and not isinstance(raw_packs, list):
        warnings.append("packs must be a list and was skipped")
        raw_packs = []
    for index, name in enumerate(raw_packs or []):
        if not isinstance(name, str) or not _ID.fullmatch(name.strip()):
            warnings.append(f"packs entry {index + 1} was not usable and was skipped")
            continue
        name = name.strip()
        pack_file = packs_dir() / f"{name}.yaml"
        if not pack_file.is_file():
            warnings.append(f"pack {name} is not available and was skipped")
            continue
        try:
            pack = _read(pack_file, f"pack {name}")
        except ConfigError as exc:
            warnings.append(f"{exc} and was skipped")
            continue
        packs.append(name)
        feeds.extend(_feeds(pack.get("feeds"), f"pack {name} feeds", warnings, name))
        watches.extend(_watches(pack.get("watches"), f"pack {name} watches", warnings, name))
    feeds.extend(_feeds(data.get("feeds"), "feeds", warnings, None))
    watches.extend(_watches(data.get("watches"), "watches", warnings, None))
    feeds = _first_by_id(feeds, "feed", warnings)[:_MAX_FEEDS]
    watches = _first_by_id(watches, "watch", warnings)[:_MAX_WATCHES]
    known = {feed.id for feed in feeds}
    for watch in watches:
        for source in watch.sources:
            if source.startswith("feed-") or source in known:
                continue
            # Store source ids such as auscert are allowed; only flag an unknown feed id
            # that looks like it was meant to be a feed.
            if source not in _STORE_SOURCES:
                warnings.append(f"watch {watch.name} names source {source}, which is not loaded")
    return Config(tuple(feeds), tuple(watches), tuple(packs), tuple(warnings))


# Intel store source ids that a watch may name besides feeds.
_STORE_SOURCES = frozenset({"asd-acsc", "auscert"})


def _read(path: Path, label: str) -> dict:
    import yaml

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"{label} is not valid YAML") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{label} must be a mapping")
    return data


def _feeds(raw, label: str, warnings: list[str], pack: str | None) -> list[Feed]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        warnings.append(f"{label} must be a list and was skipped")
        return []
    found = []
    for index, item in enumerate(raw):
        feed = _feed(item, pack)
        if feed is None:
            warnings.append(f"{label} entry {index + 1} was not usable and was skipped")
            continue
        found.append(feed)
    return found


def _feed(item, pack: str | None) -> Feed | None:
    if not isinstance(item, dict):
        return None
    ident = str(item.get("id") or "").strip()
    url = str(item.get("url") or "").strip()
    if not _ID.fullmatch(ident) or not safe_feed_url(url):
        return None
    age = item.get("max_age_days", 14)
    if isinstance(age, bool) or not isinstance(age, int) or not 1 <= age <= 365:
        return None
    categories = _terms(item.get("categories"))
    include = _terms(item.get("include"))
    if categories is None or include is None:
        return None
    label = str(item.get("label") or ident).strip()[:120] or ident
    return Feed(ident, label, url, categories, include, age, pack)


def _watches(raw, label: str, warnings: list[str], pack: str | None) -> list[Watch]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        warnings.append(f"{label} must be a list and was skipped")
        return []
    found = []
    for index, item in enumerate(raw):
        watch = _watch(item, pack)
        if watch is None:
            warnings.append(f"{label} entry {index + 1} was not usable and was skipped")
            continue
        found.append(watch)
    return found


def _watch(item, pack: str | None) -> Watch | None:
    if not isinstance(item, dict):
        return None
    name = str(item.get("name") or "").strip()
    if not _ID.fullmatch(name):
        return None
    title = str(item.get("title") or name).strip()[:120] or name
    sources = _terms(item.get("sources"))
    if sources is None or any(not _ID.fullmatch(source) for source in sources):
        return None
    parts = [_terms(item.get(key)) for key in ("any", "all", "exclude")]
    if any(part is None for part in parts):
        return None
    any_terms, all_terms, exclude = parts
    if not any_terms and not all_terms:
        return None
    days = item.get("lookback_days", 3)
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 30:
        return None
    return Watch(name, title, sources, any_terms, all_terms, exclude, days, pack)


def _terms(raw) -> tuple[str, ...] | None:
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > _MAX_TERMS:
        return None
    terms = []
    for item in raw:
        if not isinstance(item, str) or not item.strip() or len(item) > 120:
            return None
        if item.strip() not in terms:
            terms.append(item.strip())
    return tuple(terms)


def _first_by_id(items: list, kind: str, warnings: list[str]) -> list:
    seen: set[str] = set()
    kept = []
    for item in items:
        key = item.id if kind == "feed" else item.name
        if key in seen:
            warnings.append(f"{kind} {key} is defined twice; the first one is kept")
            continue
        seen.add(key)
        kept.append(item)
    return kept


def safe_feed_url(url: str) -> bool:
    """An https URL with a DNS host name: no IP literal, port, user info or fragment."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    return (
        parts.scheme == "https"
        and bool(_HOST.fullmatch(host))
        and parts.port is None
        and not parts.username
        and not parts.password
        and not parts.fragment
        and len(url) <= 500
    )
