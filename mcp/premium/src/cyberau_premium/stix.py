"""STIX export skips findings the licence does not allow out of the profile."""

from __future__ import annotations

import ipaddress
import uuid

from cyberau_premium.store import ExposureStore

_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def export_stix(store: ExposureStore) -> dict:
    skipped = 0
    objects = []
    for row in store.rows():
        if not row["stix_exportable"]:
            skipped += 1
            continue
        objects.append(_object(row))
    exported_ids = [item["x_cyberau_finding_id"] for item in objects]
    bundle_id = uuid.uuid5(_NAMESPACE, "|".join(exported_ids))
    return {
        "type": "bundle",
        "id": f"bundle--{bundle_id}",
        "objects": objects,
        "exported": len(objects),
        "skipped": skipped,
    }


def _object(row) -> dict:
    finding = row["finding_id"]
    object_id = uuid.uuid5(_NAMESPACE, finding)
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{object_id}",
        "name": row["kind"],
        "pattern_type": "stix",
        "pattern": _pattern(row["subject_type"], row["subject_value"]),
        "created": row["observed_at"],
        "modified": row["observed_at"],
        "valid_from": row["observed_at"],
        "x_cyberau_finding_id": finding,
        "x_cyberau_vendor": row["vendor"],
        "confidence_label": row["confidence"],
    }


def _pattern(subject_type: str, value: str) -> str:
    quoted = value.replace("\\", "\\\\").replace("'", "\\'")
    if subject_type in {"domain", "email_domain"}:
        return f"[domain-name:value = '{quoted}']"
    if subject_type == "ip":
        try:
            kind = "ipv6-addr" if ipaddress.ip_address(value).version == 6 else "ipv4-addr"
        except ValueError:
            kind = "x-cyberau-ip"
        return f"[{kind}:value = '{quoted}']"
    return f"[x-cyberau-{subject_type}:value = '{quoted}']"
