#!/usr/bin/env python3
"""Turn an advisory or CVE, plus its IOCs and ATT&CK techniques, into hunt query drafts.

Pure and offline. Nothing here runs a query, opens a connection, or contacts a SIEM.
Every query is marked as an untested draft for a person to review.

Input (JSON or YAML, or keyword arguments to ``generate``):

    source:      {"id": "CVE-2026-0001" or an advisory id, "url": optional https link,
                  "retrieved": optional YYYY-MM-DD from the tool envelope}
    iocs:        [{"type": "ip|domain|url|sha256|md5|email", "value": "..."}]
                 or {"ip": [...], "domain": [...]}
    techniques:  ["T1059.001", ...]
    lookback:    "30d" (optional, 1h to 365d)

IOC values come from feeds and advisories, so they are untrusted. Each value is
refanged (``hxxp``, ``[.]``, ``[@]``), checked against a strict pattern for its
type, and dropped with a reason if it does not match. Accepted values are then
escaped for the target language. Feed text never becomes query syntax.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml

STATUS = "untested draft"
NOTICE = (
    "Untested drafts. Review each query, check it against your own schema, and run it "
    "yourself. This script never runs a query against a live SIEM."
)
LANGUAGES = {
    "kql_defender": "KQL (Microsoft Defender XDR advanced hunting)",
    "kql_sentinel": "KQL (Microsoft Sentinel)",
    "spl": "SPL (Splunk CIM data models)",
    "sigma": "Sigma",
}
IOC_TYPES = ("ip", "domain", "url", "sha256", "md5", "email")
MAX_VALUES_PER_TYPE = 200
MAX_TECHNIQUES = 50
_NAMESPACE = uuid.UUID("6f1b2a4e-9c55-4d6e-8a1f-2b7c1d0e9a10")

_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_ADVISORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,79}$")
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_LOOKBACK = re.compile(r"^([1-9]\d{0,2})([hd])$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN = re.compile(rf"^(?=.{{4,253}}$){_LABEL}(?:\.{_LABEL})*\.[a-z][a-z0-9-]{{1,62}}(?<!-)$")
_LOCAL_PART = re.compile(r"^[a-z0-9](?:[a-z0-9._%+-]{0,62}[a-z0-9])?$")
_URL_CHARS = re.compile(r"^[A-Za-z0-9._~:/?#@!&()+,;=%-]+$")
_URL = re.compile(
    r"^(?P<scheme>(?i:https?))://(?P<host>\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(?P<port>:\d{1,5})?"
    r"(?P<rest>[/?#].*)?$"
)
_HASH = {"sha256": re.compile(r"^[a-f0-9]{64}$"), "md5": re.compile(r"^[a-f0-9]{32}$")}
_PLACEHOLDER = re.compile(
    r"\{\{(in|contains|suffix) ([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_]\w*)?)\}\}"
)
_SIGMA_VALUES = re.compile(r"^\{\{values(?: prefix=([^{}]*))?\}\}$")
_REFANG = (
    (re.compile(r"(?i)^hxxp(s?)://"), r"http\1://"),
    (re.compile(r"(?i)^hxxp(s?)\[:\]//"), r"http\1://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)", re.IGNORECASE), "@"),
    (re.compile(r"\[:\]"), ":"),
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class HuntInputError(ValueError):
    """The request cannot be turned into queries."""


def skill_dir() -> Path:
    return Path(__file__).resolve().parents[1]


def load_templates(path: Path | None = None) -> dict:
    target = path or skill_dir() / "references" / "hunt-templates.yaml"
    loaded = yaml.safe_load(target.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict) or not isinstance(loaded.get("templates"), list):
        raise TypeError("hunt templates need a templates list")
    attack = loaded.get("attack")
    if not isinstance(attack, dict) or not isinstance(attack.get("techniques"), dict):
        raise TypeError("hunt templates need an attack block")
    return loaded


def load_schema_citations(directory: Path | None = None) -> dict[str, str]:
    """Map each bundled KQL table name to its citation line."""
    folder = directory or skill_dir() / "references" / "schemas"
    out: dict[str, str] = {}
    for path in sorted(folder.glob("*.json")):
        item = json.loads(path.read_text(encoding="utf-8"))
        out[item["table"]] = _citation(item["source_name"], item["version"], item["retrieved"])
    return out


def load_cim(path: Path | None = None) -> dict:
    target = path or skill_dir() / "references" / "splunk-cim.yaml"
    loaded = yaml.safe_load(target.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict) or not isinstance(loaded.get("datamodels"), dict):
        raise TypeError("Splunk CIM extract needs datamodels")
    return loaded


# Escaping. Validation already limits each value to a narrow character set; these
# functions are the second line and are safe for any string.


def kql_string(value: str) -> str:
    """A KQL double-quoted string literal."""
    _reject_control(value)
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def spl_string(value: str, *, wildcard: bool = False, suffix: bool = False) -> str:
    """An SPL double-quoted value.

    ``wildcard`` wraps the value in ``*`` (contains). ``suffix`` matches ``*.value``
    (any subdomain). A literal ``*`` cannot be escaped in an SPL search, so a value
    that holds one is refused rather than turned into a wildcard.
    """
    _reject_control(value)
    if "*" in value:
        raise ValueError("an asterisk is a wildcard in SPL and cannot be escaped")
    body = value.replace("\\", "\\\\").replace('"', '\\"')
    if wildcard:
        return f'"*{body}*"'
    if suffix:
        return f'"*.{body}"'
    return f'"{body}"'


def sigma_value(value: str) -> str:
    """A Sigma string value with the wildcard and escape characters escaped."""
    _reject_control(value)
    return re.sub(r"([\\*?])", r"\\\1", value)


def _reject_control(value: str) -> None:
    if not isinstance(value, str) or _CONTROL.search(value):
        raise ValueError("control characters are not allowed in a query value")


# Refang and validate.


def refang(value: str) -> str:
    text = value.strip()
    for pattern, replacement in _REFANG:
        text = pattern.sub(replacement, text)
    return text


def normalise_ioc(kind: str, raw: object) -> tuple[str | None, str]:
    """Return the cleaned value, or None and the reason it was refused."""
    if kind not in IOC_TYPES:
        return None, f"unknown IOC type {kind}"
    if not isinstance(raw, str) or not raw.strip():
        return None, "empty value"
    if len(raw) > 2048:
        return None, "longer than 2048 characters"
    if _CONTROL.search(raw):
        return None, "contains control characters"
    value = refang(raw)
    if kind == "ip":
        if "%" in value or "/" in value:
            return None, "IPv6 scope ids and CIDR ranges are not supported"
        try:
            return str(ipaddress.ip_address(value)), ""
        except ValueError:
            return None, "not an IPv4 or IPv6 address"
    if kind == "domain":
        lowered = value.lower().rstrip(".")
        return (lowered, "") if _DOMAIN.fullmatch(lowered) else (None, "not a domain name")
    if kind in _HASH:
        lowered = value.lower()
        if _HASH[kind].fullmatch(lowered):
            return lowered, ""
        return None, f"not a {kind} hex digest"
    if kind == "email":
        local, sep, domain = value.rpartition("@")
        local, domain = local.lower(), domain.lower()
        if sep and _LOCAL_PART.fullmatch(local) and _DOMAIN.fullmatch(domain):
            return f"{local}@{domain}", ""
        return None, "not an email address"
    return _normalise_url(value)


def _normalise_url(value: str) -> tuple[str | None, str]:
    if not _URL_CHARS.fullmatch(value):
        return None, "URL has characters outside the allowed set"
    match = _URL.fullmatch(value)
    if not match:
        # The host pattern has no "@", so a URL with user:pass@ also lands here.
        return None, "not an http or https URL with a plain host"
    host = match.group("host").lower()
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        if not _DOMAIN.fullmatch(host):
            return None, "URL host is not a domain name or IP address"
    port = match.group("port") or ""
    rest = match.group("rest") or ""
    return f"{match.group('scheme').lower()}://{host}{port}{rest}", ""


def defang(value: str) -> str:
    """Defang one observable for text a person reads. Same rules as the harness."""
    if "[.]" in value or "[@]" in value or value.lower().startswith("hxxp"):
        return value
    text = re.sub(r"(?i)^http", "hxxp", value)
    return text.replace("@", "[@]").replace(".", "[.]")


# Generation.


def generate(
    source: dict,
    *,
    iocs: object = None,
    techniques: object = None,
    lookback: str = "30d",
    languages: object = None,
    templates: dict | None = None,
) -> dict:
    """Build query drafts. Raises ``HuntInputError`` when the source or options are unusable."""
    library = templates or load_templates()
    src = _source(source)
    window = _lookback(lookback)
    wanted = _languages(languages)
    accepted, rejected = _iocs(iocs)
    chosen, unmapped, bad_techniques = _techniques(techniques, library)
    schema_cites = load_schema_citations()
    cim = load_cim()
    cim_cite = _citation(cim["source_name"], cim["version"], cim["retrieved"])
    attack = library["attack"]
    warnings = list(src.pop("warnings"))
    queries: list[dict] = []
    for template in library["templates"]:
        kind = template.get("ioc")
        if kind:
            values = accepted.get(kind, [])
            if not values:
                continue
            basis = {"ioc_type": kind, "count": len(values)}
            cites = [src["citation"]]
        else:
            hits = [tid for tid in template.get("techniques", []) if tid in chosen]
            if not hits:
                continue
            values = []
            basis = {"techniques": hits}
            cites = [src["citation"]] + [
                _citation(f"MITRE ATT&CK {tid}", attack["version"], attack["retrieved"])
                for tid in hits
            ]
        for language in wanted:
            block = template.get(language)
            if not isinstance(block, dict):
                reason = template.get(f"{language}_unavailable")
                if reason:
                    warnings.append(f"{template['id']} has no {LANGUAGES[language]}: {reason}")
                continue
            entry = _entry(template, language, block, values, window, src, basis, cites)
            entry["citations"].extend(_data_citations(language, entry, schema_cites, cim_cite))
            queries.append(entry)
    if not accepted and not chosen:
        warnings.append("No usable IOC or mapped technique, so no query was drafted.")
    return {
        "status": STATUS,
        "notice": NOTICE,
        "executed": False,
        "source": {k: v for k, v in src.items() if k != "citation"} | {"citation": src["citation"]},
        "lookback": window,
        "queries": queries,
        "iocs_used": {kind: len(values) for kind, values in accepted.items()},
        "rejected": rejected,
        "unmapped_techniques": unmapped,
        "invalid_techniques": bad_techniques,
        "warnings": warnings,
    }


def _entry(template, language, block, values, window, src, basis, cites) -> dict:
    if language == "sigma":
        query = _sigma_rule(template, block, values, src)
    else:
        query = _render(block["query"], values, window, language)
    return {
        "id": f"{template['id']}:{language}",
        "template": template["id"],
        "title": template["title"],
        "language": language,
        "language_label": LANGUAGES[language],
        "status": STATUS,
        "query": query,
        "based_on": basis,
        "data_sources": list(block.get("data_sources", [])),
        "false_positives": list(template.get("false_positives", [])),
        "citations": list(cites),
    }


def _render(text: str, values: list[str], window: str, language: str) -> str:
    out = text.replace("{{lookback}}", window)

    def fill(match: re.Match[str]) -> str:
        op, field = match.group(1), match.group(2)
        if not values:
            raise HuntInputError(f"template needs values for {field}")
        if language == "spl":
            if op == "in":
                parts = [f"{field}={spl_string(v)}" for v in values]
            elif op == "contains":
                parts = [f"{field}={spl_string(v, wildcard=True)}" for v in values]
            else:
                parts = []
                for v in values:
                    parts.append(f"{field}={spl_string(v)}")
                    parts.append(f"{field}={spl_string(v, suffix=True)}")
            return "(" + " OR ".join(parts) + ")"
        if op == "in":
            return f"{field} in~ ({', '.join(kql_string(v) for v in values)})"
        if op == "contains":
            return "(" + " or ".join(f"{field} contains {kql_string(v)}" for v in values) + ")"
        return (
            "("
            + " or ".join(
                f"{field} =~ {kql_string(v)} or {field} endswith {kql_string('.' + v)}"
                for v in values
            )
            + ")"
        )

    out = _PLACEHOLDER.sub(fill, out).rstrip("\n")
    if "{{" in out or "}}" in out:
        raise HuntInputError("a template placeholder was not filled")
    return out


def _sigma_rule(template: dict, block: dict, values: list[str], src: dict) -> str:
    detection = _fill_detection(block["detection"], values)
    techniques = sorted(
        {tid for tid in template.get("techniques", [])} if not template.get("ioc") else set()
    )
    tags = [f"attack.{tid.lower()}" for tid in techniques]
    if src["kind"] == "cve":
        tags.append("cve." + src["id"][4:].lower())
    seed = json.dumps([src["id"], template["id"], values], sort_keys=True)
    rule: dict = {
        "title": f"{template['title']} ({src['id']})",
        "id": str(uuid.uuid5(_NAMESPACE, seed)),
        "status": "experimental",
        "description": (
            f"Untested draft generated from {src['id']} by the hermes-cyber-au threat-hunting "
            "skill. Review before use."
        ),
        "author": "hermes-cyber-au hunt_queries.py (draft)",
        "date": src["retrieved"],
    }
    if src.get("url"):
        rule["references"] = [src["url"]]
    if tags:
        rule["tags"] = tags
    rule["logsource"] = dict(block["logsource"])
    rule["detection"] = detection
    rule["falsepositives"] = list(template.get("false_positives", []))
    rule["level"] = "medium"
    return yaml.safe_dump(rule, sort_keys=False, allow_unicode=False, width=1000).rstrip("\n")


def _fill_detection(node, values: list[str]):
    if isinstance(node, dict):
        return {key: _fill_detection(value, values) for key, value in node.items()}
    if isinstance(node, list):
        return [_fill_detection(item, values) for item in node]
    if isinstance(node, str):
        match = _SIGMA_VALUES.fullmatch(node)
        if match:
            if not values:
                raise HuntInputError("Sigma template needs values")
            prefix = match.group(1) or ""
            return [sigma_value(prefix + value) for value in values]
        if "{{" in node:
            raise HuntInputError("unknown Sigma placeholder")
    return node


def _data_citations(language: str, entry: dict, schemas: dict[str, str], cim_cite: str) -> list:
    if language == "spl":
        return [cim_cite]
    if language.startswith("kql"):
        return [
            cite for table, cite in schemas.items() if re.search(rf"\b{table}\b", entry["query"])
        ]
    return []


def _source(source: object) -> dict:
    if not isinstance(source, dict):
        raise HuntInputError("source must be an object with an id")
    raw_id = source.get("id")
    if not isinstance(raw_id, str) or not raw_id.strip():
        raise HuntInputError("source.id is required: an advisory id or a CVE id")
    ident = raw_id.strip()
    warnings: list[str] = []
    if _CVE.fullmatch(ident.upper()):
        ident = ident.upper()
        kind = "cve"
        name = f"CVE Program {ident}"
    elif _ADVISORY.fullmatch(ident):
        kind = "advisory"
        name = f"ASD ACSC advisory {ident}"
    else:
        raise HuntInputError("source.id must be a CVE id or a short advisory id")
    url = source.get("url")
    if url is not None:
        if not isinstance(url, str) or not url.startswith("https://"):
            raise HuntInputError("source.url must be an https link")
        clean, problem = _normalise_url(url)
        if clean is None:
            raise HuntInputError(f"source.url is not usable: {problem}")
        url = clean
    retrieved = source.get("retrieved")
    if retrieved is None:
        retrieved = datetime.now(ZoneInfo("Australia/Sydney")).date().isoformat()
        warnings.append("source.retrieved was not supplied, so today's date was used.")
    elif not isinstance(retrieved, str) or not _DATE.fullmatch(retrieved):
        raise HuntInputError("source.retrieved must be YYYY-MM-DD")
    return {
        "id": ident,
        "kind": kind,
        "url": url,
        "retrieved": retrieved,
        "citation": _citation(name, "none", retrieved),
        "warnings": warnings,
    }


def _iocs(raw: object) -> tuple[dict[str, list[str]], list[dict]]:
    pairs: list[tuple[object, object]] = []
    if raw is None:
        raw = []
    if isinstance(raw, dict):
        for kind, values in raw.items():
            if not isinstance(values, list):
                values = [values]
            pairs.extend((kind, value) for value in values)
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                pairs.append((item.get("type"), item.get("value")))
            else:
                pairs.append((None, item))
    else:
        raise HuntInputError("iocs must be a list or an object keyed by type")
    accepted: dict[str, list[str]] = {}
    rejected: list[dict] = []
    for kind, value in pairs:
        kind_text = kind if isinstance(kind, str) else ""
        clean, reason = normalise_ioc(kind_text, value)
        if clean is None:
            rejected.append(_rejected(kind_text, value, reason))
            continue
        bucket = accepted.setdefault(kind_text, [])
        if clean in bucket:
            continue
        if len(bucket) >= MAX_VALUES_PER_TYPE:
            rejected.append(_rejected(kind_text, value, f"more than {MAX_VALUES_PER_TYPE} values"))
            continue
        bucket.append(clean)
    return accepted, rejected


def _rejected(kind: str, value: object, reason: str) -> dict:
    shown = value if isinstance(value, str) else repr(value)
    shown = _CONTROL.sub(" ", shown)[:80]
    return {"type": kind or "unknown", "value": defang(shown), "reason": reason, "untrusted": True}


def _techniques(raw: object, library: dict) -> tuple[set[str], list[str], list[str]]:
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise HuntInputError("techniques must be a list")
    known = set()
    for template in library["templates"]:
        known.update(template.get("techniques", []))
    chosen: set[str] = set()
    unmapped: list[str] = []
    invalid: list[str] = []
    for item in raw[:MAX_TECHNIQUES]:
        text = item.strip().upper() if isinstance(item, str) else ""
        if not _TECHNIQUE.fullmatch(text):
            invalid.append(defang(_CONTROL.sub(" ", str(item))[:40]))
            continue
        hits = {tid for tid in known if tid == text or tid.startswith(text + ".")}
        if hits:
            chosen.update(hits)
        elif text not in unmapped:
            unmapped.append(text)
    return chosen, unmapped, invalid


def _lookback(value: object) -> str:
    if not isinstance(value, str):
        raise HuntInputError("lookback must be text such as 30d")
    match = _LOOKBACK.fullmatch(value.strip())
    if not match:
        raise HuntInputError("lookback must be 1h to 999h, or 1d to 365d")
    number, unit = int(match.group(1)), match.group(2)
    if unit == "d" and number > 365:
        raise HuntInputError("lookback must be 365d or less")
    return f"{number}{unit}"


def _languages(raw: object) -> list[str]:
    if raw is None:
        return list(LANGUAGES)
    if not isinstance(raw, list) or not raw:
        raise HuntInputError("languages must be a non-empty list")
    out = []
    for item in raw:
        if item not in LANGUAGES:
            raise HuntInputError(f"unknown language {item}")
        if item not in out:
            out.append(item)
    return out


def _citation(name: str, version: str, retrieved: str) -> str:
    clean = name.replace(",", " ")
    return f"Source: {clean}, {version.replace(',', ' ') or 'none'}, retrieved {retrieved}"


# Output.


def to_markdown(pack: dict) -> str:
    fence = {"kql_defender": "kusto", "kql_sentinel": "kusto", "spl": "spl", "sigma": "yaml"}
    lines = [
        f"# Hunt query drafts for {pack['source']['id']}",
        "",
        f"Status: {pack['status']}. {pack['notice']}",
        "",
        "Proposal: review these drafts before anyone runs them. "
        "This skill does not run a hunt and does not create an analytics rule.",
        "",
    ]
    for query in pack["queries"]:
        lines.extend(
            [
                f"## {query['title']}: {query['language_label']}",
                "",
                f"Status: {query['status']}",
                "",
                f"```{fence[query['language']]}",
                query["query"],
                "```",
                "",
                "Data sources needed:",
            ]
        )
        lines.extend(f"- {item}" for item in query["data_sources"])
        lines.append("")
        lines.append("False positives:")
        lines.extend(f"- {item}" for item in query["false_positives"])
        lines.append("")
        lines.extend(query["citations"])
        lines.append("")
    if pack["rejected"]:
        lines.append("## Values not used")
        lines.append("")
        for item in pack["rejected"]:
            lines.append(f"- {item['type']} `{item['value']}`: {item['reason']}")
        lines.append("")
    if pack["unmapped_techniques"]:
        lines.append("## Techniques with no template")
        lines.append("")
        lines.append(", ".join(pack["unmapped_techniques"]))
        lines.append("Draft these by hand with the threat-hunting procedure.")
        lines.append("")
    for warning in pack["warnings"]:
        lines.append(f"Note: {warning}")
    return "\n".join(lines).rstrip("\n") + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Draft hunt queries from an advisory or CVE.")
    parser.add_argument("path", nargs="?", type=Path, help="JSON or YAML request. Reads stdin.")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args(argv)
    try:
        text = args.path.read_text(encoding="utf-8") if args.path else sys.stdin.read()
        request = yaml.safe_load(text)
        if not isinstance(request, dict):
            raise HuntInputError("the request must be an object")
        pack = generate(
            request.get("source"),
            iocs=request.get("iocs"),
            techniques=request.get("techniques"),
            lookback=request.get("lookback", "30d"),
            languages=request.get("languages"),
        )
    except (OSError, yaml.YAMLError, HuntInputError, TypeError, ValueError) as exc:
        json.dump({"status": "error", "error": str(exc), "queries": []}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 2
    if args.format == "markdown":
        sys.stdout.write(to_markdown(pack))
    else:
        json.dump(pack, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
