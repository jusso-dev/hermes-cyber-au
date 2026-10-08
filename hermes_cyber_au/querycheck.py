"""Offline syntax and schema checks. A query is ready only when both pass.

Write and response verbs are refused here. This module does not run the query.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .common import repo_root

KQL_WORDS = {
    "where", "project", "extend", "summarize", "join", "union", "parse", "distinct",
    "top", "take", "sort", "order", "by", "count", "dcount", "sum", "min", "max",
    "avg", "make_set", "ago", "datetime", "has", "contains", "startswith", "endswith",
    "in", "has_any", "iff", "iif", "case", "tostring", "tolong", "toint", "bin",
    "let", "as", "on", "kind", "inner", "leftouter", "rightouter", "fullouter",
    "and", "or", "not", "true", "false", "between", "project-away", "project-keep",
    "project-rename", "mv-expand", "mv-apply", "parse-where", "scan", "make-series",
    "render", "timechart", "barchart", "with", "source", "step", "declare", "query_parameters",
    "isnull", "isnotnull", "isempty", "isnotempty", "strcat", "hash", "floor", "ceiling",
    "abs", "round", "now", "startofday", "endofday", "format_datetime", "split",
    "todynamic", "todatetime", "tolower", "toupper", "extract", "countif", "arg_max",
    "arg_min", "take_any", "bag_pack", "pack", "dynamic", "timespan", "int", "long",
    "string", "bool", "real", "decimal", "guid", "materialize", "view", "datatable",
    "range", "print", "fork", "facet", "lookup", "external_table",
}
SQL_WORDS = {
    "select", "from", "where", "and", "or", "not", "in", "is", "null", "as", "on",
    "join", "left", "right", "inner", "outer", "full", "group", "by", "order",
    "limit", "offset", "having", "distinct", "case", "when", "then", "else", "end",
    "with", "cast", "like", "between", "exists", "union", "all", "true", "false",
    "asc", "desc", "count", "sum", "min", "max", "avg", "date", "timestamp",
    "lower", "upper", "coalesce", "nullif", "substring", "trim", "unnest",
    "element_at", "regexp_like", "array", "struct", "row", "over", "partition",
    "rows", "interval", "day", "hour", "minute", "second", "cross", "using",
}
LOGS_WORDS = {
    "fields", "filter", "stats", "sort", "limit", "parse", "display", "dedup",
    "head", "tail", "like", "by", "as", "and", "or", "not", "in", "count", "sum",
    "avg", "min", "max", "earliest", "latest", "desc", "asc",
}
LOGS_BUILTINS = {"@timestamp", "@message", "@logstream", "@log", "@ptr"}
WRITE_SQL = re.compile(
    r"(?i)\b(insert|update|delete|drop|alter|create|grant|revoke|merge|copy|unload|"
    r"call|execute|truncate|msck|vacuum|into\s+outfile)\b"
)
WRITE_KQL = re.compile(
    r"(?i)(?:^|\n)\s*\.(set|drop|delete|create|alter|append|ingest|rename|replace|set-or-append|set-or-replace)\b"
    r"|\b(externaldata|evaluate)\b|\|\s*into\b"
)


def _load(name: str) -> dict:
    path = repo_root() / "knowledge" / "schemas" / name
    return json.loads(path.read_text(encoding="utf-8"))


def sentinel_schema() -> dict[str, set[str]]:
    raw = _load("sentinel.json")
    return {
        table: {column["name"].lower() for column in spec["columns"]}
        for table, spec in raw.items()
    }


def aws_schema() -> dict[str, set[str]]:
    raw = _load("aws.json")
    return {name: {column.lower() for column in columns} for name, columns in raw["columns"].items()}


def _strip_comments_and_strings(query: str) -> str:
    without_block = re.sub(r"/\*.*?\*/", " ", query, flags=re.S)
    without_line = re.sub(r"--.*?$|//.*?$", " ", without_block, flags=re.M)
    return re.sub(r"'(?:''|[^'])*'|\"(?:\\\"|[^\"])*\"", " '' ", without_line)


def _balanced(query: str) -> str | None:
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    for char in query:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            continue
        if in_single or in_double:
            continue
        if char in "([{":
            stack.append(char)
        elif char in pairs:
            if not stack or stack.pop() != pairs[char]:
                return "unbalanced brackets"
    if in_single or in_double:
        return "unbalanced quotes"
    if stack:
        return "unbalanced brackets"
    return None


def _schema_comment(query: str) -> str:
    match = re.search(r"(?i)cyber-au-schema:\s*([a-z0-9_-]+)", query)
    return match.group(1).lower() if match else ""


def check_kql(query: str, schema: dict[str, set[str]] | None = None) -> dict:
    schema = schema if schema is not None else sentinel_schema()
    errors: list[str] = []
    balance = _balanced(query)
    if balance:
        errors.append(balance)
    stripped = _strip_comments_and_strings(query)
    if WRITE_KQL.search(stripped):
        errors.append("write or external verb is not allowed")
    tables = {name.lower(): name for name in schema}
    used_tables = []
    for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", stripped):
        if token.lower() in tables and token.lower() not in {item.lower() for item in used_tables}:
            used_tables.append(tables[token.lower()])
    if not used_tables:
        errors.append("no known Sentinel or Defender table")
    known_columns: set[str] = set()
    for table in used_tables:
        known_columns |= schema[table]
    # Column positions: after where/project/extend/summarize/by and before a comparison.
    column_uses = re.findall(
        r"(?i)\b(?:where|project|extend|summarize|by|on)\s+([A-Za-z_][A-Za-z0-9_]*)",
        stripped,
    )
    for name in column_uses:
        lowered = name.lower()
        if lowered in KQL_WORDS or lowered in tables or lowered in known_columns:
            continue
        errors.append(f"unknown column {name}")
    ready = not errors
    return {
        "language": "kql",
        "ready": ready,
        "errors": errors,
        "tables": used_tables,
        "evidence_class": "prepared_not_observed",
    }


def check_sql(query: str, schema: dict[str, set[str]] | None = None) -> dict:
    schema = schema if schema is not None else aws_schema()
    errors: list[str] = []
    balance = _balanced(query)
    if balance:
        errors.append(balance)
    declared = _schema_comment(query)
    if declared not in schema:
        errors.append("missing or unknown cyber-au-schema comment")
        columns: set[str] = set()
    else:
        columns = schema[declared]
    stripped = _strip_comments_and_strings(query)
    if WRITE_SQL.search(stripped):
        errors.append("write verb is not allowed")
    if not re.match(r"(?is)\s*(select|with)\b", stripped):
        errors.append("only a SELECT or WITH query is accepted")
    idents = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?\b", stripped)
    saw_column = False
    for ident in idents:
        lowered = ident.lower()
        head = lowered.split(".", 1)[0]
        if lowered in SQL_WORDS or head in SQL_WORDS or lowered == declared:
            continue
        if lowered in columns or head in {column.split(".", 1)[0] for column in columns}:
            saw_column = True
            continue
        # FROM aliases and table functions are not columns. Flag only dotted
        # names and bare names that sit in a select/where list of known shape.
    dotted = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*)\b", stripped)
    for ident in dotted:
        if ident.lower() not in columns:
            errors.append(f"unknown column {ident}")
    if declared and not saw_column and not dotted:
        # A query can still be valid if it uses bare column names.
        bare_hits = [
            ident for ident in idents
            if ident.lower() in columns
        ]
        saw_column = bool(bare_hits)
    if declared and not saw_column and not any(ident.lower() in columns for ident in idents):
        errors.append("no known column for the declared schema")
    ready = not errors
    return {
        "language": "sql",
        "ready": ready,
        "errors": errors,
        "schema": declared,
        "evidence_class": "prepared_not_observed",
    }


def check_logs_insights(query: str, schema: dict[str, set[str]] | None = None) -> dict:
    """CloudWatch Logs Insights. Ready only with a known schema comment and known fields."""
    schema = schema if schema is not None else aws_schema()
    errors: list[str] = []
    balance = _balanced(query)
    if balance:
        errors.append(balance)
    declared = _schema_comment(query)
    if declared not in schema:
        errors.append("missing or unknown cyber-au-schema comment")
        columns: set[str] = set()
    else:
        columns = schema[declared]
    stripped = _strip_comments_and_strings(query)
    if WRITE_SQL.search(stripped) or re.search(r"(?i)\b(delete|drop|create)\b", stripped):
        errors.append("write verb is not allowed")
    if not re.search(r"(?i)\b(fields|filter|stats|parse)\b", stripped):
        errors.append("not a Logs Insights query")
    fields = re.findall(r"@[A-Za-z]+|\b[A-Za-z_][A-Za-z0-9_.]*\b", stripped)
    saw = False
    for field in fields:
        lowered = field.lower()
        if lowered in LOGS_WORDS or lowered in LOGS_BUILTINS or lowered == declared:
            if lowered in LOGS_BUILTINS:
                saw = True
            continue
        if lowered in columns:
            saw = True
            continue
    if declared and not saw:
        errors.append("no known Logs Insights field")
    return {
        "language": "logs_insights",
        "ready": not errors,
        "errors": errors,
        "schema": declared,
        "evidence_class": "prepared_not_observed",
    }


def check_query(language: str, query: str) -> dict:
    kind = (language or "").lower().replace("-", "_")
    if kind == "kql":
        return check_kql(query)
    if kind in {"sql", "cloudtrail_lake", "athena"}:
        return check_sql(query)
    if kind in {"logs_insights", "cloudwatch"}:
        return check_logs_insights(query)
    return {"language": kind, "ready": False, "errors": ["unsupported language"], "evidence_class": "prepared_not_observed"}
