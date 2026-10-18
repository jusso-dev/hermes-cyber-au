#!/usr/bin/env python3
"""Check a KQL hunt against the bundled table schemas. No network.

The checker refuses a query that is not ready. It does not run the query.
A column missing from a partial schema is not confirmed. It is not a claim
that Microsoft's table lacks that column.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# KQL has no block comments. Strings are matched first so a "//" inside a
# string literal is not read as the start of a comment.
_TOKEN = re.compile(
    r"@\"(?:[^\"]|\"\")*\"|@'(?:[^']|'')*'"
    r"|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'"
    r"|//[^\n]*"
)
# Any statement that starts with a dot is a management command.
_MANAGEMENT = re.compile(r"(?:^|;)\s*(\.[A-Za-z][A-Za-z0-9_-]*)")
_FORBIDDEN = re.compile(
    r"(?i)\b(?:externaldata|evaluate\s+(?:http_request|http_request_post|"
    r"sql_request|mysql_request|postgresql_request|azure_digital_twins_query_request))\b"
)
_TABLE_OP = (
    "has_any|has_all|has_cs|!has|!contains|!startswith|!endswith|"
    "contains|startswith|endswith|has|"
    "!in~|in~|!in|in|matches regex|between|>=|<=|==|!=|=~|!~|>|<"
)
_COLUMN_OP = re.compile(
    rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:{_TABLE_OP})(?!\w)",
    re.IGNORECASE,
)
_OPERATOR = re.compile(r"\|\s*[A-Za-z][A-Za-z0-9_-]*")
_ALIAS = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=(?![=~])")
_TYPED = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[A-Za-z_]")
_IDENT = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]*")

_FUNCTIONS = {
    "abs",
    "ago",
    "and",
    "asc",
    "avg",
    "between",
    "bin",
    "by",
    "case",
    "ceiling",
    "count",
    "countif",
    "datetime",
    "dcount",
    "desc",
    "distinct",
    "endofday",
    "endswith",
    "extend",
    "extract",
    "false",
    "floor",
    "format_datetime",
    "has",
    "has_all",
    "has_any",
    "has_cs",
    "hash_sha256",
    "iff",
    "in",
    "isempty",
    "isnotempty",
    "isnotnull",
    "isnull",
    "join",
    "kind",
    "limit",
    "make_list",
    "make_set",
    "matches",
    "max",
    "min",
    "not",
    "now",
    "on",
    "or",
    "order",
    "parse_json",
    "project",
    "regex",
    "sort",
    "startofday",
    "startswith",
    "strcat",
    "strcat_array",
    "sum",
    "summarize",
    "take",
    "todatetime",
    "toint",
    "tolong",
    "toreal",
    "tostring",
    "true",
    "union",
    "where",
    # keywords, operators and types that appear bare in a query
    "bool",
    "datetime",
    "decimal",
    "dynamic",
    "fullouter",
    "guid",
    "hasprefix",
    "hassuffix",
    "inner",
    "innerunique",
    "int",
    "leftanti",
    "leftouter",
    "leftsemi",
    "left",
    "long",
    "null",
    "nulls",
    "real",
    "right",
    "rightanti",
    "rightouter",
    "rightsemi",
    "string",
    "timespan",
    "with",
    "first",
    "last",
    "contains",
    "contains_cs",
    "endswith_cs",
    "startswith_cs",
    "hint",
    "isfuzzy",
    "let",
}


def schema_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "references" / "schemas"


def load_schemas(directory: Path) -> dict[str, dict]:
    """Load ``*.json`` table schemas. Raises ``ValueError`` on a bad file."""
    tables: dict[str, dict] = {}
    paths = sorted(directory.glob("*.json"))
    if not paths:
        raise ValueError(f"no schema files in {directory}")
    for path in paths:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise TypeError(f"{path.name} must be a JSON object")
        name = loaded.get("table")
        columns = loaded.get("columns")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{path.name} needs a table name")
        if name in tables:
            raise ValueError(f"duplicate table {name}")
        if not isinstance(columns, dict) or not columns:
            raise ValueError(f"{path.name} needs columns")
        if not isinstance(loaded.get("time_column"), str):
            raise TypeError(f"{path.name} needs a time_column")
        if loaded["time_column"] not in columns:
            raise ValueError(f"{path.name} time_column is not a column")
        for key, value in columns.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise TypeError(f"{path.name} columns must map names to types")
        tables[name] = loaded
    return tables


def check_query(query: str, schemas: dict[str, dict]) -> dict:
    """Return a ready flag, errors, and citation fields for the tables used."""
    errors: list[str] = []
    stripped = _strip(query)
    if not stripped.strip():
        return _result(False, [], ["query is empty"], schemas)
    management = _MANAGEMENT.search(stripped)
    if management:
        errors.append(
            f"management command {management.group(1)} is not a hunt. The query is not ready."
        )
    forbidden = _FORBIDDEN.search(stripped)
    if forbidden:
        errors.append(f"{forbidden.group(0)} is not a hunt. The query is not ready.")
    if '"' in stripped or "'" in stripped:
        errors.append("unterminated string literal. The query is not ready.")
    tables = [name for name in schemas if re.search(rf"\b{re.escape(name)}\b", stripped)]
    if not tables and not errors:
        errors.append("no bundled table name found. Put the table name in the query.")
    known = _known_columns(schemas, tables)
    table_names = set(schemas)
    for column in sorted(_columns_used(stripped) - known - table_names):
        where = ", ".join(tables) if tables else "the bundled schemas"
        errors.append(
            f"column {column} is not confirmed in the bundled schema for {where}. "
            "The bundled schema is a partial extract. Drop the column or stop. "
            "Do not say the column is absent from the vendor table."
        )
    for name in tables:
        time_column = schemas[name]["time_column"]
        if time_column not in _compared_columns(stripped):
            errors.append(f"no time bound on {time_column}. The query is not ready.")
    return _result(not errors, tables, errors, schemas)


def _result(ready: bool, tables: list[str], errors: list[str], schemas: dict[str, dict]) -> dict:
    citations = []
    for name in tables:
        item = schemas[name]
        citations.append(
            {
                "table": name,
                "source_name": item.get("source_name", name),
                "version": item.get("version", "none"),
                "retrieved": item.get("retrieved", ""),
            }
        )
    return {"ready": ready, "tables": tables, "errors": errors, "citations": citations}


def _strip(query: str) -> str:
    return _TOKEN.sub(lambda m: " " if m.group(0).startswith("//") else " 0 ", query)


def _known_columns(schemas: dict[str, dict], tables: list[str]) -> set[str]:
    names: set[str] = set()
    for table in tables:
        names.update(schemas[table]["columns"])
    return names


def _compared_columns(text: str) -> set[str]:
    return {match.group(1) for match in _COLUMN_OP.finditer(text)}


def _columns_used(text: str) -> set[str]:
    """Return every bare identifier that is not a keyword, call, alias or member."""
    body = _OPERATOR.sub(" ", text)
    defined = {match.group(1) for match in _ALIAS.finditer(body)}
    defined.update(match.group(1) for match in _TYPED.finditer(body))
    used: set[str] = set()
    for match in _IDENT.finditer(body):
        name = match.group(0)
        start, end = match.span()
        if start > 0 and body[start - 1] == ".":
            continue
        if body[end:].lstrip().startswith("("):
            continue
        if name in defined or name.lower() in _FUNCTIONS:
            continue
        used.add(name)
    return used


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check KQL against bundled hunt schemas.")
    parser.add_argument("path", nargs="?", type=Path, help="File containing the query")
    parser.add_argument("--query", help="Query text. Overrides the file.")
    parser.add_argument("--schemas", type=Path, default=schema_dir())
    args = parser.parse_args(argv)
    try:
        if args.query is not None:
            query = args.query
        elif args.path is not None:
            query = args.path.read_text(encoding="utf-8")
        else:
            query = sys.stdin.read()
        payload = check_query(query, load_schemas(args.schemas))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        payload = {"ready": False, "tables": [], "errors": [str(exc)], "citations": []}
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if payload["ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
