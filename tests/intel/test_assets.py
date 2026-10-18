"""Asset inventory import and matching. Synthetic fixtures only, no network."""

from __future__ import annotations

import ast
import importlib.util
import json
import socket
import stat
import sys
from pathlib import Path

import pytest
from store import assets

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "assets"
CSV = FIXTURES / "inventory.csv"
SBOM = FIXTURES / "sbom.cdx.json"
BRIEFING = ROOT / "skills" / "daily-briefing" / "scripts" / "briefing.py"


def _briefing():
    spec = importlib.util.spec_from_file_location("cyberau_test_briefing_assets", BRIEFING)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module  # dataclasses look the module up by name
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def no_network(monkeypatch):
    """Fail the test if anything opens a socket connection."""
    calls: list[object] = []

    def refuse(self, address, *args, **kwargs):
        calls.append(address)
        raise AssertionError(f"inventory code tried to connect to {address}")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    return calls


def test_csv_import_maps_columns_and_validates() -> None:
    result = assets.import_file(CSV)
    names = [asset.name for asset in result.assets]
    assert names == ["North gateway", "Desk systems", "Plant historian", "Mail relay 2"]
    north, desk, plant, relay = result.assets
    assert north.exposure == "internet"
    assert north.extra["criticality"] == "critical"
    assert north.extra["environment"] == "it"
    assert north.extra["hostname"] == "gw1.example.com"
    assert north.extra["source"] == "csv:inventory.csv"
    assert desk.exposure == "internal" and desk.extra["environment"] == "it"
    assert plant.extra["environment"] == "ot"
    assert relay.extra["environment"] == "cloud"
    assert "#" not in relay.name
    assert len(result.skipped) == 1 and "row 6" in result.skipped[0]


def test_csv_without_a_product_column_is_refused() -> None:
    with pytest.raises(assets.InventoryError, match="product, cpe or purl"):
        assets.import_csv("host,owner\nh1,team\n")


def test_cyclonedx_import_walks_nested_components() -> None:
    result = assets.import_file(SBOM)
    by_product = {asset.product: asset for asset in result.assets}
    assert set(by_product) == {"examplelib", "example-parser", "tinyzip"}
    lib = by_product["examplelib"]
    assert lib.name == "Billing API: examplelib 2.4.0"
    assert lib.vendor == "examplelib"  # no supplier, so the product name stands in
    assert lib.get("purl") == "pkg:pypi/examplelib@2.4.0"
    assert lib.exposure == "internal"  # never assumed internet-facing
    parser = by_product["example-parser"]
    assert parser.vendor == "com.example"
    assert parser.get("purl") == "pkg:maven/com.example/example-parser@1.9.3"
    assert by_product["tinyzip"].vendor == "Example Compression Pty Ltd"
    assert len(result.skipped) == 1  # the component with no name


def test_cyclonedx_xml_and_other_json_are_refused(tmp_path: Path) -> None:
    xml = tmp_path / "bom.xml"
    xml.write_text('<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5"/>')
    with pytest.raises(assets.InventoryError, match="XML"):
        assets.import_file(xml)
    other = tmp_path / "other.json"
    other.write_text('{"spdxVersion": "SPDX-2.3"}')
    with pytest.raises(assets.InventoryError, match="CycloneDX"):
        assets.import_file(other)


def test_written_inventory_is_read_by_the_daily_briefing(tmp_path: Path) -> None:
    path = tmp_path / "assets.yaml"
    combined = assets.import_file(CSV).assets + assets.import_file(SBOM).assets
    assets.write_inventory(path, combined)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    briefing = _briefing()
    loaded = briefing.load_assets(path.read_text(encoding="utf-8"))
    assert [item.name for item in loaded] == [item.name for item in combined]
    assert assets.read_inventory(path)[0].get("cpe").startswith("cpe:2.3:a:examplevendor")
    yaml = pytest.importorskip("yaml")
    parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert parsed["assets"][2]["version"] == "7.2"  # stays a string


def test_example_template_loads() -> None:
    loaded = assets.read_inventory(assets.TEMPLATE_PATH)
    assert [item.name for item in loaded][0] == "North gateway"
    _briefing().load_assets(assets.TEMPLATE_PATH.read_text(encoding="utf-8"))


def test_merge_replaces_same_name_and_keeps_others() -> None:
    old = [assets.Asset("A", "v", "p"), assets.Asset("B", "v", "p")]
    new = [assets.Asset("b", "v2", "p2"), assets.Asset("C", "v", "p")]
    merged = assets.merge(old, new)
    assert [(item.name, item.vendor) for item in merged] == [
        ("A", "v"),
        ("b", "v2"),
        ("C", "v"),
    ]


def test_match_methods_cpe_purl_and_labelled_fallback() -> None:
    inventory = assets.import_file(CSV).assets + assets.import_file(SBOM).assets
    found = assets.match(inventory, cpes=["cpe:2.3:a:examplevendor:edgegate:*:*:*:*:*:*:*:*"])
    assert [(item.asset.name, item.method) for item in found] == [("North gateway", "cpe")]

    found = assets.match(inventory, purls=["pkg:pypi/ExampleLib@2.3.9"])
    assert [(item.asset.product, item.method) for item in found] == [("examplelib", "purl")]

    found = assets.match(inventory, vendor="Exampleos", product="Workstation Pro")
    assert [(item.asset.name, item.method) for item in found] == [
        ("Desk systems", "vendor-product-fuzzy")
    ]
    assert "Check the version" in found[0].detail

    # A CPE for a product the asset has no CPE for still matches, labelled as fuzzy.
    found = assets.match(
        inventory, cpes=["cpe:2.3:a:examplecontrols:historian_server:7.2:*:*:*:*:*:*:*"]
    )
    assert [(item.asset.name, item.method) for item in found] == [
        ("Plant historian", "vendor-product-fuzzy")
    ]
    assert assets.match(inventory, vendor="Unrelated", product="Widget") == []


def test_cli_import_list_and_match(tmp_path: Path, capsys, no_network) -> None:
    path = tmp_path / "assets.yaml"
    assert assets.main(["import", str(CSV), "--inventory", str(path)]) == 0
    assert assets.main(["import", str(SBOM), "--inventory", str(path), "--owner", "apps"]) == 0
    capsys.readouterr()
    assert assets.main(["list", "--inventory", str(path)]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert len(listed) == 7
    assert {row["owner"] for row in listed if row.get("source") == "sbom:sbom.cdx.json"} == {"apps"}
    assert (
        assets.main(
            [
                "match",
                "--inventory",
                str(path),
                "--cpe",
                "cpe:2.3:a:examplecompression:tinyzip:0.4:*:*:*:*:*:*:*",
            ]
        )
        == 0
    )
    matched = json.loads(capsys.readouterr().out)
    assert [(row["asset"]["product"], row["method"]) for row in matched] == [("tinyzip", "cpe")]
    assert no_network == []


def test_cpe_part_mismatch_is_not_a_product_match() -> None:
    asset = assets.Asset(
        "Example",
        "examplevendor",
        "edgegate",
        extra={
            "cpe": "cpe:2.3:h:examplevendor:edgegate:1:*:*:*:*:*:*:*",
        },
    )
    assert (
        assets.match(
            [asset],
            cpes=[
                "cpe:2.3:a:examplevendor:edgegate:*:*:*:*:*:*:*:*",
            ],
        )
        == []
    )
    found = assets.match(
        [asset],
        cpes=[
            "cpe:2.3:h:examplevendor:edgegate:*:*:*:*:*:*:*:*",
        ],
    )
    assert found[0].method == "cpe"
    assert "Check the version" in found[0].detail


def test_cli_strict_and_dry_run_write_nothing(tmp_path: Path, capsys) -> None:
    path = tmp_path / "assets.yaml"
    assert assets.main(["import", str(CSV), "--inventory", str(path), "--strict"]) == 1
    assert not path.exists()
    assert assets.main(["import", str(CSV), "--inventory", str(path), "--dry-run"]) == 0
    assert not path.exists()
    assert "North gateway" in capsys.readouterr().out


def test_cli_without_a_path_says_how_to_set_one(monkeypatch, capsys) -> None:
    monkeypatch.delenv("CYBERAU_DATA_DIR", raising=False)
    monkeypatch.delenv("HERMES_HOME", raising=False)
    assert assets.main(["list"]) == 2
    assert "CYBERAU_DATA_DIR" in capsys.readouterr().err


def test_default_path_uses_the_profile_data_dir(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    assert assets.default_path() == tmp_path / "assets.yaml"


def test_inventory_module_has_no_network_imports() -> None:
    tree = ast.parse(Path(assets.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & {"socket", "http", "httpx", "requests", "urllib3", "ssl"}
    # urllib is imported only for unquote.
    assert "urlopen" not in Path(assets.__file__).read_text(encoding="utf-8")


def test_cyberau_mcp_assets_command(tmp_path: Path, capsys) -> None:
    from cyberau_common.cli import main as cli_main

    path = tmp_path / "assets.yaml"
    assert cli_main(["assets", "import", str(CSV), "--inventory", str(path)]) == 0
    assert "imported 4 assets" in capsys.readouterr().out
