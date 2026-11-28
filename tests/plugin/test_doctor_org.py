"""cyber-au doctor reports org.yaml and the active sector packs. No network."""

from __future__ import annotations

import importlib
import importlib.util
import shutil
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins" / "cyber-au"
MODULE = "cyber_au_doctor_org_plugin"


def _load():
    loaded = sys.modules.get(MODULE)
    if loaded is None:
        spec = importlib.util.spec_from_file_location(
            MODULE, PLUGIN / "__init__.py", submodule_search_locations=[str(PLUGIN)]
        )
        assert spec is not None and spec.loader is not None
        loaded = importlib.util.module_from_spec(spec)
        sys.modules[MODULE] = loaded
        spec.loader.exec_module(loaded)
    return importlib.import_module(f"{MODULE}.doctor")


doctor = _load()


def _ctx(root: Path, home: Path, today: date = date(2026, 11, 28)):
    return doctor.Context(
        root=root,
        home=home,
        environ={},
        offline=True,
        today=today,
        hermes_version=lambda: "hermes 0.23.0",
        health=lambda _name, _live: (0, "ok"),
    )


def _org(home: Path, text: str) -> None:
    path = home / "plugin-data" / "cyber-au" / "org.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _ids(checks):
    return {item.id: item for item in checks}


def test_missing_org_yaml_is_a_warning_with_the_setup_fix(tmp_path: Path):
    found = _ids(doctor.check_org(_ctx(ROOT, tmp_path)))
    assert found["org.profile"].status == "warn"
    assert "hermes cyber-au setup" in found["org.profile"].fix
    assert found["org.packs"].status == "ok"
    assert found["org.packs"].detail == "active: none (sector general)"


def test_active_pack_is_reported(tmp_path: Path):
    _org(tmp_path, "sector: energy-water\nenvironments: [it, ot]\n")
    found = _ids(doctor.check_org(_ctx(ROOT, tmp_path)))
    assert found["org.profile"].status == "ok"
    assert found["org.packs"].status == "ok"
    assert found["org.packs"].detail == "active: energy-water 0.1.0 (sector energy-water)"


def test_overdue_review_and_missing_pack_warn(tmp_path: Path):
    _org(tmp_path, "sector: retail\nsector_packs: [energy-water, no-such-pack]\n")
    found = _ids(doctor.check_org(_ctx(ROOT, tmp_path, today=date(2027, 6, 1))))
    packs = found["org.packs"]
    assert packs.status == "warn"
    assert "not installed: no-such-pack" in packs.detail
    assert "review overdue: energy-water/" in packs.detail


def test_org_yaml_holding_a_key_fails(tmp_path: Path):
    _org(tmp_path, "sector: health\nnvd_api_key: doctor-org-not-a-real-value\n")
    found = _ids(doctor.check_org(_ctx(ROOT, tmp_path)))
    assert found["org.profile"].status == "fail"
    assert "doctor-org-not-a-real-value" not in found["org.profile"].detail


def test_broken_local_pack_is_counted(tmp_path: Path):
    root = tmp_path / "dist"
    shutil.copytree(ROOT / "packs", root / "packs")
    local = tmp_path / "plugin-data" / "cyber-au" / "packs" / "broken-pack"
    local.mkdir(parents=True)
    (local / "pack.yaml").write_text("name: broken-pack\n", encoding="utf-8")
    _org(tmp_path, "sector: health\n")
    packs = _ids(doctor.check_org(_ctx(root, tmp_path)))["org.packs"]
    assert packs.status == "warn"
    assert "1 pack(s) failed validation" in packs.detail
    assert "health 0.1.0" in packs.detail


def test_doctor_report_includes_org_checks(tmp_path: Path):
    ids = {item.id for item in doctor.collect_checks(_ctx(ROOT, tmp_path))}
    assert {"org.profile", "org.packs"} <= ids
