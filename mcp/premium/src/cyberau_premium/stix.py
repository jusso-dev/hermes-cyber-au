"""STIX export skips findings the licence does not allow out of the profile."""

from __future__ import annotations

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
        "pattern": f"[domain-name:value = '{row['subject_value']}']",
        "valid_from": row["observed_at"],
        "x_cyberau_finding_id": finding,
        "x_cyberau_vendor": row["vendor"],
        "confidence_label": row["confidence"],
    }
