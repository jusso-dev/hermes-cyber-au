"""Re-pull allowlisted sources, keep prior versions, and record the diff.

Fetched pages are data. A failed fetch keeps the last good snapshot.
The first run is a baseline and is not a change digest.
"""

from __future__ import annotations

import json
import os
import re
import socket
import ssl
import sys
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .common import (
    instruction_like,
    parse_day,
    repo_root,
    scrub_public,
    sha256_bytes,
    sha256_text,
    sydney_now,
)
from .corpus import snapshots_root, write_jsonl
from .fetch import FetchError, fetch_url, github_commit, raw_github
from .htmltext import chunk_page, html_to_text, page_is_usable, prepare_text
from .oscal import parse_catalog

MANIFEST_NAME = "manifest.json"
CHANGES_NAME = "changes.json"
E8_STRATEGY_PHRASES = (
    "patch applications",
    "patch operating systems",
    "multi-factor authentication",
    "restrict administrative privileges",
    "application control",
    "restrict microsoft office macros",
    "user application hardening",
    "regular backups",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return sydney_now().date().isoformat()


def _day_before(iso_day: str) -> str:
    year, month, day = (int(part) for part in iso_day.split("-"))
    return (date(year, month, day) - timedelta(days=1)).isoformat()


def _sources() -> dict[str, Any]:
    path = repo_root() / "knowledge" / "sources.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _manifest_path() -> Path:
    return repo_root() / "knowledge" / MANIFEST_NAME


def _changes_path() -> Path:
    return repo_root() / "knowledge" / CHANGES_NAME


def _load_manifest() -> dict[str, Any]:
    path = _manifest_path()
    if not path.exists():
        return {"schema": "hermes-cyber-au-manifest/v1", "sources": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def _load_changes() -> dict[str, Any]:
    path = _changes_path()
    if not path.exists():
        return {"schema": "hermes-cyber-au-changes/v1", "runs": []}
    return json.loads(path.read_text(encoding="utf-8"))


def _guard_text(text: str) -> str:
    return scrub_public(prepare_text(text)[0])


def _chunk_shell(source: dict[str, Any], *, url: str, title: str, text: str, version: str, published: str) -> dict[str, Any]:
    cleaned = _guard_text(text)
    content_hash = sha256_text(cleaned)
    return {
        "chunk_id": f"{source['id']}:{sha256_text(url)[:12]}:{content_hash[:12]}",
        "source_id": source["id"],
        "publisher": source.get("publisher") or "",
        "title": _guard_text(title)[:300] or source.get("title") or source["id"],
        "section": url,
        "control_id": "",
        "text": cleaned,
        "version": version or "unspecified",
        "published": published,
        "retrieved_at": _today(),
        "url": url,
        "content_sha256": content_hash,
        "valid_from": _today(),
        "valid_to": None,
        "trust_tier_offered": "upstream_official",
        "evidence_class": "prepared_not_observed",
        "instructions": "data_only",
        "instruction_like": instruction_like(cleaned),
    }


def _read_chunks(source_id: str) -> list[dict[str, Any]]:
    path = snapshots_root() / source_id / "chunks.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _write_text_if_changed(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == body:
        return
    path.write_text(body, encoding="utf-8")


def _scrub_obj(value: Any) -> Any:
    if isinstance(value, str):
        return scrub_public(value)
    if isinstance(value, list):
        return [_scrub_obj(item) for item in value]
    if isinstance(value, dict):
        return {key: _scrub_obj(item) for key, item in value.items()}
    return value


def _write_source(source_id: str, chunks: list[dict[str, Any]], header: dict[str, Any]) -> None:
    base = snapshots_root() / source_id
    body = "".join(json.dumps(_scrub_obj(row), ensure_ascii=False) + "\n" for row in chunks)
    _write_text_if_changed(base / "chunks.jsonl", body)
    _write_text_if_changed(base / "header.json", json.dumps(_scrub_obj(header), indent=2) + "\n")


def _hosts(source: dict[str, Any]) -> set[str]:
    return {host.lower() for host in source.get("hosts") or []}


def _close_replaced(existing: list[dict[str, Any]], new_urls: set[str], today: str) -> None:
    end = _day_before(today)
    for chunk in existing:
        if chunk.get("valid_to") in (None, "") and chunk.get("url") in new_urls:
            start = chunk.get("valid_from") or today
            chunk["valid_to"] = end if end >= start else start


def ingest_ism(source: dict[str, Any], *, resolve_main: bool, apply_pin: bool) -> dict[str, Any]:
    hosts = _hosts(source)
    repo = source["repo"]
    failures: list[dict[str, str]] = []
    by_sha: dict[str, tuple[list[dict[str, Any]], dict[str, Any]]] = {}
    pins = list(source.get("pins") or [])
    main_sha = ""
    if resolve_main:
        try:
            main_sha = github_commit(repo, "refs/heads/main", hosts)
        except FetchError as exc:
            failures.append({"url": f"https://github.com/{repo}", "error": exc.code, "detail": exc.detail[:300]})
    wanted: list[tuple[str, str]] = []
    for pin in pins:
        wanted.append((pin["git_sha"], pin.get("role") or "pinned"))
    if main_sha and all(main_sha != sha for sha, _role in wanted):
        wanted.append((main_sha, "upstream"))

    existing_chunks = _read_chunks(source["id"])
    existing_header_path = snapshots_root() / source["id"] / "header.json"
    existing_versions = []
    if existing_header_path.exists():
        existing_versions = json.loads(existing_header_path.read_text(encoding="utf-8")).get("versions") or []
    for sha, role in wanted:
        cached_header = next((item for item in existing_versions if item.get("git_sha") == sha), None)
        cached_chunks = [chunk for chunk in existing_chunks if chunk.get("mirror_sha") == sha]
        if cached_header and cached_chunks:
            by_sha[sha] = (cached_chunks, dict(cached_header))
            continue
        try:
            parsed = _fetch_ism_pin(source, sha, role)
        except (FetchError, ValueError, KeyError, json.JSONDecodeError) as exc:
            code = exc.code if isinstance(exc, FetchError) else type(exc).__name__
            detail = exc.detail if isinstance(exc, FetchError) else str(exc)
            failures.append({"url": f"https://github.com/{repo}/tree/{sha}", "error": code, "detail": detail[:300]})
            continue
        by_sha[sha] = parsed

    if not by_sha:
        kept = _read_chunks(source["id"])
        return {
            "chunks": kept,
            "header": {"versions": [], "failures": failures, "kept_last_good": bool(kept)},
            "failures": failures,
            "pin_update": None,
        }

    ordered = sorted(by_sha.values(), key=lambda item: item[1]["published"])
    for index, (chunks, header) in enumerate(ordered):
        header["valid_to"] = None
        if index < len(ordered) - 1:
            nxt = ordered[index + 1][1]["published"]
            header["valid_to"] = _day_before(nxt)
            for chunk in chunks:
                chunk["valid_to"] = header["valid_to"]
        else:
            for chunk in chunks:
                chunk["valid_to"] = None
    flat: list[dict[str, Any]] = []
    for chunks, _header in ordered:
        for chunk in chunks:
            original = chunk.get("text") or ""
            cleaned = _guard_text(original)
            chunk["text"] = cleaned
            if cleaned != original:
                chunk["content_sha256"] = sha256_text(cleaned)
            for key in ("title", "section"):
                if isinstance(chunk.get(key), str):
                    chunk[key] = _guard_text(chunk[key])
            chunk["instruction_like"] = instruction_like(cleaned)
        flat.extend(chunks)
    versions = [header for _chunks, header in ordered]
    pin_update = None
    if apply_pin and main_sha and any(sha == main_sha and role == "upstream" for sha, role in wanted) and main_sha in by_sha:
        pin_update = _apply_pin(source, main_sha, by_sha[main_sha][1])
    header = {"source_id": source["id"], "versions": versions, "failures": failures, "pin_update": pin_update}
    _write_source(source["id"], flat, header)
    return {"chunks": flat, "header": header, "failures": failures, "pin_update": pin_update}


def _fetch_ism_pin(source: dict[str, Any], sha: str, role: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    hosts = _hosts(source)
    repo = source["repo"]
    profiles: dict[str, dict[str, Any]] = {}
    catalog_doc = None
    catalog_url = ""
    profile_failures: list[str] = []
    for filename in source.get("files") or []:
        try:
            result = raw_github(repo, sha, filename, hosts)
        except FetchError as exc:
            if filename == "ISM_catalog.json":
                raise
            profile_failures.append(f"{filename}: {exc.code}")
            continue
        payload = result.json()
        if filename == "ISM_catalog.json":
            catalog_doc = payload
            catalog_url = result.final_url
            continue
        if isinstance(payload, dict):
            profiles[filename] = payload
    if not isinstance(catalog_doc, dict):
        raise FetchError("shape", "ISM catalogue was not a JSON object")
    mirror = catalog_url or f"https://raw.githubusercontent.com/{repo}/{sha}/ISM_catalog.json"
    chunks, header = parse_catalog(
        catalog_doc,
        git_sha=sha,
        mirror_url=mirror,
        canonical_url=source.get("canonical_url") or "https://www.cyber.gov.au/ism",
        profiles=profiles,
    )
    header["role"] = role
    header["e8_profiles"] = sorted(name for name in profiles if "E8" in name)
    header["profile_failures"] = profile_failures
    return chunks, header


def _apply_pin(source: dict[str, Any], sha: str, header: dict[str, Any]) -> dict[str, str]:
    document = _sources()
    for item in document["sources"]:
        if item["id"] != source["id"]:
            continue
        pins = item.setdefault("pins", [])
        for pin in pins:
            if pin.get("role") == "current":
                pin["role"] = "previous"
        pins.append({"role": "current", "git_sha": sha, "label": f"ISM {header.get('version')}"})
        break
    path = repo_root() / "knowledge" / "sources.json"
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return {"git_sha": sha, "version": str(header.get("version") or "")}


def ingest_html(source: dict[str, Any]) -> dict[str, Any]:
    hosts = _hosts(source)
    failures: list[dict[str, str]] = []
    pages: list[tuple[str, str, str]] = []
    urls = list(source.get("urls") or [])
    seen = set(urls)
    follow_budget = int(source.get("follow_limit") or 0) if source.get("follow_same_host") else 0
    index = 0
    while index < len(urls):
        url = urls[index]
        index += 1
        try:
            fetched = fetch_url(url, hosts, timeout=60)
        except FetchError as exc:
            failures.append({"url": url, "error": exc.code, "detail": exc.detail[:300]})
            continue
        plain_path = urlparse(fetched.final_url).path.lower()
        if plain_path.endswith((".yaml", ".yml", ".md", ".txt")):
            text = fetched.text()
            if not page_is_usable(text):
                failures.append({"url": fetched.final_url, "error": "shape", "detail": "text file was too short"})
                continue
            pages.append((fetched.final_url, source.get("title") or "text", text))
            continue
        if _is_pdf(fetched.content_type, fetched.final_url, fetched.body):
            pages.append((fetched.final_url, source.get("title") or "PDF", _pdf_pointer(fetched)))
            continue
        title, text, links = html_to_text(fetched.text())
        if not page_is_usable(text):
            failures.append({"url": fetched.final_url, "error": "shape", "detail": "page text was too short"})
            continue
        pages.append((fetched.final_url, title, text))
        if follow_budget <= 0:
            continue
        for href in links:
            if follow_budget <= 0:
                break
            absolute = _same_host_link(fetched.final_url, href, hosts)
            if not absolute or absolute in seen:
                continue
            if not _worth_following(absolute):
                continue
            seen.add(absolute)
            urls.append(absolute)
            follow_budget -= 1
    if not pages:
        kept = _read_chunks(source["id"])
        header = {"source_id": source["id"], "failures": failures, "kept_last_good": bool(kept), "content_sha256": ""}
        if kept:
            _write_header_only(source["id"], header)
        return {"chunks": kept, "failures": failures, "changed": False, "header": header}
    chunks: list[dict[str, Any]] = []
    for url, title, text in pages:
        version = _version_hint(title, text)
        for part in chunk_page(text):
            row = _chunk_shell(source, url=url, title=title, text=part, version=version, published="")
            row["chunk_id"] = f"{row['chunk_id']}:{len(chunks)}"
            chunks.append(row)
    digest = sha256_text("\n".join(chunk["content_sha256"] for chunk in chunks))
    previous = _load_manifest().get("sources", {}).get(source["id"], {})
    previous_hash = previous.get("content_sha256") or ""
    if previous_hash == digest:
        existing = _read_chunks(source["id"])
        if existing:
            return {"chunks": existing, "failures": failures, "changed": False, "header": {"content_sha256": digest}}
    existing = _read_chunks(source["id"])
    if previous_hash and existing:
        _close_replaced(existing, {chunk["url"] for chunk in chunks}, _today())
        chunks = [chunk for chunk in existing if chunk.get("valid_to")] + chunks
    header = {
        "source_id": source["id"],
        "content_sha256": digest,
        "chunk_count": sum(1 for chunk in chunks if not chunk.get("valid_to")),
        "failures": failures,
        "retrieved_at": _today(),
    }
    _write_source(source["id"], chunks, header)
    return {"chunks": chunks, "failures": failures, "changed": bool(previous_hash) and previous_hash != digest, "header": header}


def _write_header_only(source_id: str, header: dict[str, Any]) -> None:
    base = snapshots_root() / source_id
    base.mkdir(parents=True, exist_ok=True)
    (base / "header.json").write_text(json.dumps(_scrub_obj(header), indent=2) + "\n", encoding="utf-8")


def _is_pdf(content_type: str, url: str, body: bytes) -> bool:
    return "pdf" in content_type.lower() or url.lower().endswith(".pdf") or body.startswith(b"%PDF")


def _pdf_pointer(fetched) -> str:
    return (
        "This pack stored a PDF by URL and SHA-256 only. The text was not extracted. "
        "Do not quote the document from memory. "
        f"URL: {fetched.final_url} SHA-256: {fetched.sha256} Bytes: {len(fetched.body)}."
    )


def _same_host_link(base: str, href: str, hosts: set[str]) -> str:
    from urllib.parse import urljoin, urlparse

    if not href or href.startswith(("#", "mailto:", "javascript:")):
        return ""
    absolute = urljoin(base, href)
    parsed = urlparse(absolute)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in hosts:
        return ""
    # Facet filters on the listing page stall. Keep the path and drop the query.
    return parsed._replace(query="", fragment="").geturl()


def _worth_following(url: str) -> bool:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.query:
        return False
    path = parsed.path.lower()
    if any(path.endswith(suffix) for suffix in (".png", ".jpg", ".jpeg", ".css", ".js", ".zip", ".svg", ".gif", ".pdf")):
        return False
    parts = [part for part in path.split("/") if part]
    for marker in ("alert", "advisory", "publication"):
        if marker in parts and parts.index(marker) + 1 < len(parts):
            return True
    return False


def _version_hint(title: str, text: str) -> str:
    match = re.search(r"\b[Vv]ersion\s+(\d+\.\d+(?:\.\d+)?)\b", f"{title}\n{text[:800]}")
    if match:
        return match.group(1)
    match = re.search(r"\bV(\d+\.\d+)\b", title)
    return match.group(1) if match else "unspecified"


def _atlas_entries(text: str) -> list[tuple[str, str, str]]:
    """Pull tactic, technique, and mitigation id, name, and description. Skip case studies."""
    wanted = {"tactics", "techniques", "mitigations"}
    section = ""
    current_id = ""
    name = ""
    parts: list[str] = []
    collecting = False
    found: list[tuple[str, str, str]] = []

    def finish() -> None:
        nonlocal current_id, name, parts, collecting
        if current_id and name:
            description = " ".join(part.strip().strip("'\"") for part in parts if part.strip())
            found.append((current_id, name.strip().strip("'\""), description))
        current_id = ""
        name = ""
        parts = []
        collecting = False

    for line in text.splitlines():
        if re.fullmatch(r"[a-z-]+:", line):
            finish()
            section = line[:-1]
            continue
        if section not in wanted:
            continue
        matched = re.fullmatch(r"  (AML\.[A-Za-z0-9.]+):", line)
        if matched:
            finish()
            current_id = matched.group(1)
            continue
        if collecting and re.match(r"    [A-Za-z0-9-]+:", line) and not line.startswith("     "):
            collecting = False
        if line.startswith("    name:") and current_id:
            name = line.split(":", 1)[1].strip()
            continue
        if line.startswith("    description:"):
            collecting = True
            parts = [line.split(":", 1)[1].strip()]
            continue
        if collecting:
            parts.append(line.strip())
    finish()
    return found


def ingest_atlas(source: dict[str, Any]) -> dict[str, Any]:
    hosts = _hosts(source)
    failures: list[dict[str, str]] = []
    pointer_url = (source.get("urls") or [""])[0]
    try:
        pointer = fetch_url(pointer_url, hosts, timeout=60)
        filename = pointer.text().strip().split("/")[-1]
        if not re.fullmatch(r"ATLAS-\d{4}\.\d{2}(?:\.\d+)?\.yaml", filename):
            raise FetchError("shape", "ATLAS pointer did not name a versioned file")
        document_url = pointer_url.rsplit("/", 1)[0] + "/" + filename
        fetched = fetch_url(document_url, hosts, timeout=60)
        entries = _atlas_entries(fetched.text())
        if len(entries) < 10:
            raise FetchError("shape", "ATLAS file did not contain technique entries")
    except (FetchError, UnicodeError) as exc:
        code = exc.code if isinstance(exc, FetchError) else type(exc).__name__
        detail = exc.detail if isinstance(exc, FetchError) else str(exc)
        failures.append({"url": pointer_url, "error": code, "detail": detail[:300]})
        kept = _read_chunks(source["id"])
        return {"chunks": kept, "failures": failures, "changed": False}
    version = filename.removeprefix("ATLAS-").removesuffix(".yaml")
    chunks = []
    for entry_id, name, description in entries:
        text = f"{entry_id}: {name}"
        if description:
            text = f"{text}\n{description}"
        row = _chunk_shell(source, url=document_url, title=name, text=text, version=version, published="")
        row["chunk_id"] = f"mitre-atlas:{version}:{entry_id}"
        row["technique_id"] = entry_id
        chunks.append(row)
    digest = sha256_text("\n".join(chunk["chunk_id"] + chunk["content_sha256"] for chunk in chunks))
    previous = _load_manifest().get("sources", {}).get(source["id"], {})
    previous_hash = previous.get("content_sha256") or ""
    if previous_hash == digest:
        existing = _read_chunks(source["id"])
        if existing:
            return {"chunks": existing, "failures": failures, "changed": False, "sha": version}
    header = {
        "source_id": source["id"],
        "version": version,
        "content_sha256": digest,
        "chunk_count": len(chunks),
        "url": document_url,
        "failures": failures,
    }
    _write_source(source["id"], chunks, header)
    return {"chunks": chunks, "failures": failures, "changed": bool(previous_hash) and previous_hash != digest, "sha": version}


def ingest_attack(source: dict[str, Any]) -> dict[str, Any]:
    hosts = _hosts(source)
    failures: list[dict[str, str]] = []
    try:
        sha = github_commit(source["repo"], source.get("ref") or "refs/heads/master", hosts)
        prior = snapshots_root() / source["id"] / "header.json"
        if prior.exists():
            old = json.loads(prior.read_text(encoding="utf-8"))
            cached = _read_chunks(source["id"])
            if old.get("git_sha") == sha and cached:
                return {"chunks": cached, "failures": [], "changed": False, "sha": sha, "header": old}
        fetched = _fetch_large(source, sha)
        document = json.loads(fetched.body.decode("utf-8"))
    except (FetchError, json.JSONDecodeError, UnicodeError) as exc:
        code = exc.code if isinstance(exc, FetchError) else type(exc).__name__
        detail = exc.detail if isinstance(exc, FetchError) else str(exc)
        failures.append({"url": f"https://github.com/{source['repo']}", "error": code, "detail": detail[:300]})
        kept = _read_chunks(source["id"])
        return {"chunks": kept, "failures": failures, "changed": False, "sha": ""}
    chunks = []
    for item in document.get("objects") or []:
        if item.get("type") != "attack-pattern":
            continue
        if item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        external = ""
        url = "https://attack.mitre.org/"
        for ref in item.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                external = str(ref["external_id"])
                url = str(ref.get("url") or url)
                break
        name = str(item.get("name") or "").strip()
        if not external or not name:
            continue
        text = f"{external}: {name}\nURL: {url}\nMITRE ATT&CK. Technique id and name only."
        row = _chunk_shell(source, url=url, title=name, text=text, version=sha[:12], published="")
        row["chunk_id"] = f"mitre-attack:{external}"
        row["control_id"] = ""
        row["technique_id"] = external
        chunks.append(row)
    digest = sha256_text("\n".join(chunk["chunk_id"] + chunk["content_sha256"] for chunk in chunks))
    previous = _load_manifest().get("sources", {}).get(source["id"], {})
    previous_hash = previous.get("content_sha256") or ""
    if previous_hash == digest:
        existing = _read_chunks(source["id"])
        if existing:
            return {"chunks": existing, "failures": failures, "changed": False, "sha": sha, "header": {"content_sha256": digest, "git_sha": sha}}
    header = {"source_id": source["id"], "git_sha": sha, "technique_count": len(chunks), "content_sha256": digest, "failures": failures}
    _write_source(source["id"], chunks, header)
    return {"chunks": chunks, "failures": failures, "changed": bool(previous_hash), "sha": sha, "header": header}


def _fetch_large(source: dict[str, Any], sha: str):
    """Download the ATT&CK STIX bundle. The raw file is not stored in git."""
    from urllib.parse import urlparse

    from .fetch import USER_AGENT, FetchResult

    url = f"https://raw.githubusercontent.com/{source['repo']}/{sha}/{source['file']}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    from .fetch import _ORIG_GETADDRINFO, _ipv4_getaddrinfo

    socket.getaddrinfo = _ipv4_getaddrinfo
    try:
        with urllib.request.urlopen(request, timeout=120, context=ssl.create_default_context()) as response:
            body = response.read(60_000_001)
            final_url = response.geturl()
            status = getattr(response, "status", 200)
            content_type = response.headers.get("Content-Type", "")
    except (TimeoutError, OSError) as exc:
        raise FetchError("transport", f"{url}: {exc}") from exc
    finally:
        socket.getaddrinfo = _ORIG_GETADDRINFO
    if len(body) > 60_000_000:
        raise FetchError("too_large", url)
    host = (urlparse(final_url).hostname or "").lower()
    if host not in _hosts(source) | {"raw.githubusercontent.com"}:
        raise FetchError("host_not_allowlisted", host)
    return FetchResult(url=url, final_url=final_url, status=status, body=body, content_type=content_type, sha256=sha256_bytes(body))


def _ism_diff(previous_chunks: list[dict[str, Any]], current_chunks: list[dict[str, Any]]) -> dict[str, list[str]]:
    def current_map(chunks: list[dict[str, Any]]) -> dict[str, str]:
        found = {}
        for chunk in chunks:
            if chunk.get("source_id") != "asd-ism-oscal" or chunk.get("valid_to"):
                continue
            control_id = chunk.get("control_id") or ""
            if control_id:
                found[control_id] = chunk.get("content_sha256") or ""
        return found

    old = current_map(previous_chunks)
    new = current_map(current_chunks)
    return {
        "new": sorted(set(new) - set(old)),
        "withdrawn": sorted(set(old) - set(new)),
        "changed": sorted(control_id for control_id in set(old) & set(new) if old[control_id] != new[control_id]),
    }


def _strategies(chunks: list[dict[str, Any]]) -> list[str]:
    blob = "\n".join(chunk.get("text") or "" for chunk in chunks if chunk.get("source_id") == "asd-essential-eight").lower()
    if not blob:
        return []
    found = [phrase for phrase in E8_STRATEGY_PHRASES if phrase in blob]
    return found if len(found) == len(E8_STRATEGY_PHRASES) else []


def _append_changelog(run: dict[str, Any]) -> None:
    path = repo_root() / "CHANGELOG.md"
    lines = [f"## {run['date']}", ""]
    if run.get("baseline"):
        lines.append("Baseline snapshot. This is the first stored copy, not a change digest.")
        lines.append("")
    lines.append(f"Material change: {'yes' if run.get('material') else 'no'}.")
    ism = run.get("ism") or {}
    lines.append(
        f"ISM control IDs: {len(ism.get('new') or [])} new, {len(ism.get('changed') or [])} changed, {len(ism.get('withdrawn') or [])} withdrawn."
    )
    for item in run.get("sources") or []:
        state = item.get("state")
        lines.append(f"- {item['id']}: {state}.")
        if item.get("url"):
            lines.append(f"  Source: {item['url']}")
    if ism.get("new") or ism.get("changed") or ism.get("withdrawn"):
        lines.append("Flagged ISM control IDs are listed in knowledge/changes.json for this date.")
    for failure in run.get("failures") or []:
        lines.append(f"- Failed {failure.get('url')}: {failure.get('error')}. Last good copy kept where one existed.")
    lines.append("")
    block = scrub_public("\n".join(lines))
    if path.exists():
        path.write_text(path.read_text(encoding="utf-8").rstrip() + "\n\n" + block, encoding="utf-8")
    else:
        path.write_text("# Changelog\n\n" + block, encoding="utf-8")


def _draft_stale(changed_ids: list[str]) -> list[str]:
    if not changed_ids:
        return []
    needle = {control_id.lower() for control_id in changed_ids}
    stale: list[str] = []
    skills = repo_root() / "skills"
    if skills.exists():
        for path in sorted(skills.glob("*/SKILL.md")):
            text = path.read_text(encoding="utf-8").lower()
            hits = sorted(control_id for control_id in needle if control_id in text)
            if hits:
                stale.append(f"{path.relative_to(repo_root())}: {', '.join(hits)}")
    if not stale:
        return []
    draft = repo_root() / "drafts" / "stale-skills.md"
    draft.parent.mkdir(parents=True, exist_ok=True)
    body = [
        "# Stale skills",
        "",
        "These files mention an ISM control ID whose ingested text changed.",
        "This draft is for a person to review. It was not applied to the skill.",
        "Use skill_manage with write_approval, or edit the skill on a pull request.",
        "",
    ]
    body.extend(f"- {line}" for line in stale)
    body.append("")
    draft.write_text("\n".join(body), encoding="utf-8")
    return stale


def _maybe_digest(run: dict[str, Any]) -> str:
    if not run.get("material"):
        return ""
    links = [item.get("url") for item in run.get("sources") or [] if item.get("url")]
    ism = run.get("ism") or {}
    text = (
        f"hermes-cyber-au {run['date']}: material change. "
        f"ISM new {len(ism.get('new') or [])}, changed {len(ism.get('changed') or [])}, "
        f"withdrawn {len(ism.get('withdrawn') or [])}. "
        + " ".join(links[:8])
    ).strip()
    webhook = os.environ.get("CYBER_AU_DIGEST_WEBHOOK", "").strip()
    if webhook.startswith("https://"):
        payload = json.dumps({"text": text}).encode("utf-8")
        request = urllib.request.Request(
            webhook,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "hermes-cyber-au/0.1"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=20, context=ssl.create_default_context()) as response:
                response.read(1024)
        except Exception:
            pass
    return text


def refresh(*, resolve_main: bool = True, apply_pin: bool = False, rebuild_index: bool = True) -> dict[str, Any]:
    """Pull every allowlisted source. Baseline runs set material to false."""
    document = _sources()
    previous_manifest = _load_manifest()
    baseline = not previous_manifest.get("built_at")
    previous_chunks = []
    if not baseline:
        from .corpus import load_corpus

        previous_chunks = load_corpus().chunks
    failures: list[dict[str, str]] = []
    source_rows: list[dict[str, Any]] = []
    collected: list[dict[str, Any]] = []
    attack_sha = ""
    for source in document.get("sources") or []:
        print(f"refresh {source['id']}", file=sys.stderr, flush=True)
        kind = source.get("kind")
        if kind == "ism-oscal":
            result = ingest_ism(source, resolve_main=resolve_main, apply_pin=apply_pin)
            state = "loaded" if result["chunks"] else "failed"
        elif kind == "mitre-attack":
            result = ingest_attack(source)
            attack_sha = result.get("sha") or ""
            state = "loaded" if result["chunks"] else "failed"
        elif kind == "atlas-yaml":
            result = ingest_atlas(source)
            state = "loaded" if result["chunks"] else "failed"
        else:
            result = ingest_html(source)
            state = "loaded" if any(not chunk.get("valid_to") for chunk in result["chunks"]) else "failed"
        for failure in result.get("failures") or []:
            failure = dict(failure)
            failure["source_id"] = source["id"]
            failures.append(failure)
        if result.get("failures") and result.get("chunks"):
            state = "kept_last_good" if not any(not chunk.get("valid_to") for chunk in result["chunks"]) else "loaded_with_failures"
        source_rows.append(
            {
                "id": source["id"],
                "state": state,
                "url": (source.get("urls") or [source.get("canonical_url") or ""])[0],
                "material_on_change": bool(source.get("material_on_change")),
                "changed": bool(result.get("changed")),
            }
        )
        collected.extend(result.get("chunks") or [])
    ism_delta = {"new": [], "changed": [], "withdrawn": []}
    if not baseline:
        ism_delta = _ism_diff(previous_chunks, collected)
    strategies = _strategies(collected)
    strategy_path = repo_root() / "knowledge" / "essential-eight-strategies.json"
    _write_text_if_changed(
        strategy_path,
        json.dumps(
            {
                "source_id": "asd-essential-eight",
                "strategies": strategies,
                "note": "Listed only when every phrase was present in the fetched Essential Eight pages.",
            },
            indent=2,
        )
        + "\n",
    )
    previous_failures = {
        (item.get("source_id"), item.get("url"), item.get("error"))
        for item in previous_manifest.get("failures") or []
    }
    new_failures = [
        item
        for item in failures
        if (item.get("source_id"), item.get("url"), item.get("error")) not in previous_failures
    ]
    content_changed = any(row["changed"] and row["material_on_change"] for row in source_rows)
    ism_moved = any(ism_delta[key] for key in ("new", "changed", "withdrawn"))
    material = (not baseline) and (content_changed or ism_moved or bool(new_failures))
    built_at = _utc_now()
    manifest = {
        "schema": "hermes-cyber-au-manifest/v1",
        "built_at": built_at,
        "baseline": baseline,
        "sources": {},
        "failures": failures,
        "ism": ism_delta,
        "mitre_attack_sha": attack_sha,
        "essential_eight_strategies_verified": len(strategies) == len(E8_STRATEGY_PHRASES),
    }
    for source in document.get("sources") or []:
        header_path = snapshots_root() / source["id"] / "header.json"
        header = json.loads(header_path.read_text(encoding="utf-8")) if header_path.exists() else {}
        versions = header.get("versions") or []
        count = header.get("chunk_count") or header.get("technique_count")
        if versions:
            count = sum(item.get("control_count") or 0 for item in versions)
        manifest["sources"][source["id"]] = {
            "content_sha256": header.get("content_sha256") or "",
            "versions": versions,
            "chunk_count": count,
        }
        if header.get("versions"):
            manifest["sources"][source["id"]]["content_sha256"] = sha256_text(
                json.dumps([item.get("git_sha") for item in header["versions"]])
            )
    run = {
        "date": _today(),
        "built_at": built_at,
        "baseline": baseline,
        "material": material,
        "ism": ism_delta,
        "sources": source_rows,
        "failures": failures,
        "new_failures": new_failures,
    }
    if baseline or material:
        _manifest_path().write_text(json.dumps(_scrub_obj(manifest), indent=2) + "\n", encoding="utf-8")
        changes = _load_changes()
        changes["runs"].append(_scrub_obj(run))
        _changes_path().write_text(json.dumps(changes, indent=2) + "\n", encoding="utf-8")
        _append_changelog(run)
    stale = _draft_stale(ism_delta["changed"] + ism_delta["withdrawn"]) if not baseline else []
    eval_questions = {"added": 0, "updated": 0}
    if not baseline and any(ism_delta[key] for key in ("new", "changed", "withdrawn")):
        from .evalscore import sync_material_questions

        eval_questions = sync_material_questions(ism_delta)
    if rebuild_index and collected and (baseline or material):
        from .index import open_index

        index_path = repo_root() / "knowledge" / "index.sqlite"
        index = open_index(index_path, collected)
        index.rebuild(collected)
        index.close()
    digest = _maybe_digest(run) if material else ""
    return {
        "baseline": baseline,
        "material": material,
        "digest": digest,
        "ism": ism_delta,
        "failures": failures,
        "sources": source_rows,
        "chunks": len(collected),
        "stale_skills": stale,
        "strategies_verified": len(strategies) == len(E8_STRATEGY_PHRASES),
        "eval_questions": eval_questions,
    }
