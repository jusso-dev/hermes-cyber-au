"""Signed data packs: build, verify, import, and every refusal. No network.

Keys are generated in each test's temporary directory. None is committed.
"""

from __future__ import annotations

import io
import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cyberau_common import datapack
from cyberau_common.cli import main as cli_main
from cyberau_common.datapack import DataPackError

WHEN = datetime(2026, 11, 28, 1, 2, 3, tzinfo=UTC)


@pytest.fixture
def keys(tmp_path: Path) -> tuple[Path, Path]:
    private = tmp_path / "keys" / "datapack.key"
    public = tmp_path / "keys" / "datapack.pub"
    datapack.generate_keypair(private, public)
    return private, public


@pytest.fixture
def source(tmp_path: Path) -> Path:
    root = tmp_path / "source"
    _write(root / "mcp" / "asd-ism" / "data" / "releases.json", '{"release": "v2026.11.1"}\n')
    _write(root / "mcp" / "asd-ism" / "data" / "v2026.11.1" / "controls.json", "[]\n")
    _write(root / "intel" / "snapshots" / "public-2026-11-27.sqlite.zst", "zstd-bytes")
    _write(root / "mcp" / "asd-ism" / "src" / "code.py", "print('not data')\n")
    return root


@pytest.fixture
def profile(tmp_path: Path) -> Path:
    home = tmp_path / "profile"
    _write(home / "mcp" / "asd-ism" / "data" / "releases.json", '{"release": "old"}\n')
    return home


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _build(source: Path, out: Path, private: Path, **kwargs) -> dict:
    return datapack.build_pack(source, out, private, now=kwargs.pop("now", WHEN), **kwargs)


def _import(pack: Path, public: Path, profile: Path, **kwargs) -> dict:
    state = kwargs.pop("state", profile / "plugin-data" / "cyber-au" / "datapack-state.json")
    return datapack.import_pack(pack, public, root=profile, state_path=state, **kwargs)


def _members(pack: Path) -> dict[str, bytes]:
    with tarfile.open(pack, "r:gz") as archive:
        return {info.name: archive.extractfile(info).read() for info in archive if info.isfile()}


def _repack(pack: Path, members: dict[str, bytes], extra: list[tarfile.TarInfo] = ()) -> None:
    with tarfile.open(pack, "w:gz") as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        for info in extra:
            archive.addfile(info)


def _tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_round_trip_installs_only_data(tmp_path, keys, source, profile):
    private, public = keys
    pack = tmp_path / "pack.tar.gz"
    built = _build(source, pack, private, label="weekly")
    assert built["files"] == 3
    names = set(_members(pack))
    assert "files/mcp/asd-ism/src/code.py" not in names
    assert {"manifest.json", "manifest.json.sig"} <= names

    verified = datapack.verify_pack(pack, public)
    assert verified["created"] == "2026-11-28T01:02:03Z"

    result = _import(pack, public, profile)
    assert result["imported"] == 3
    releases = profile / "mcp" / "asd-ism" / "data" / "releases.json"
    assert json.loads(releases.read_text()) == {"release": "v2026.11.1"}
    assert (profile / "intel" / "snapshots" / "public-2026-11-27.sqlite.zst").is_file()
    assert not (profile / "mcp" / "asd-ism" / "src").exists()
    assert not (profile / ".datapack-staging").exists()
    state = json.loads((profile / "plugin-data" / "cyber-au" / "datapack-state.json").read_text())
    assert state["created"] == "2026-11-28T01:02:03Z"
    assert state["label"] == "weekly"


def test_private_key_is_mode_600_and_never_overwritten(tmp_path, keys):
    private, public = keys
    assert private.stat().st_mode & 0o777 == 0o600
    assert b"PRIVATE KEY" in private.read_bytes()
    assert b"PUBLIC KEY" in public.read_bytes()
    with pytest.raises(DataPackError, match="already exists"):
        datapack.generate_keypair(private, tmp_path / "other.pub")


def test_keygen_refuses_a_path_inside_a_git_checkout(tmp_path):
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    with pytest.raises(DataPackError, match="git checkout"):
        datapack.generate_keypair(tmp_path / "repo" / "k.key", tmp_path / "k.pub")
    assert not (tmp_path / "repo" / "k.key").exists()


def test_tampered_file_is_refused_and_nothing_is_written(tmp_path, keys, source, profile):
    private, public = keys
    pack = tmp_path / "pack.tar.gz"
    _build(source, pack, private)
    members = _members(pack)
    members["files/mcp/asd-ism/data/releases.json"] = b'{"release": "evil"}\n'
    _repack(pack, members)
    before = _tree(profile)
    with pytest.raises(DataPackError, match="SHA-256|size"):
        _import(pack, public, profile)
    assert _tree(profile) == before
    assert not (profile / ".datapack-staging").exists()


def test_tampered_manifest_is_refused(tmp_path, keys, source, profile):
    private, public = keys
    pack = tmp_path / "pack.tar.gz"
    _build(source, pack, private)
    members = _members(pack)
    manifest = json.loads(members["manifest.json"])
    manifest["label"] = "changed"
    members["manifest.json"] = json.dumps(manifest).encode()
    _repack(pack, members)
    before = _tree(profile)
    with pytest.raises(DataPackError, match="signature does not match"):
        _import(pack, public, profile)
    assert _tree(profile) == before


def test_unsigned_pack_is_refused(tmp_path, keys, source, profile):
    private, public = keys
    pack = tmp_path / "pack.tar.gz"
    _build(source, pack, private)
    members = _members(pack)
    del members["manifest.json.sig"]
    _repack(pack, members)
    with pytest.raises(DataPackError, match="not signed"):
        _import(pack, public, profile)


def test_pack_signed_by_another_key_is_refused(tmp_path, keys, source, profile):
    _, public = keys
    other_private = tmp_path / "other" / "k.key"
    datapack.generate_keypair(other_private, tmp_path / "other" / "k.pub")
    pack = tmp_path / "pack.tar.gz"
    _build(source, pack, other_private)
    with pytest.raises(DataPackError, match="signature does not match"):
        _import(pack, public, profile)


def test_extra_unlisted_member_is_refused(tmp_path, keys, source, profile):
    private, public = keys
    pack = tmp_path / "pack.tar.gz"
    _build(source, pack, private)
    members = _members(pack)
    members["files/mcp/asd-ism/data/extra.json"] = b"{}"
    _repack(pack, members)
    with pytest.raises(DataPackError, match="does not list"):
        _import(pack, public, profile)


@pytest.mark.parametrize(
    "name",
    [
        "files/../../escape.txt",
        "files/mcp/asd-ism/data/../../../../escape.txt",
        "/etc/escape.txt",
        "../escape.txt",
        "files/mcp/asd-ism/src/code.py",
        "files/.env",
        "other/thing.json",
    ],
)
def test_path_traversal_and_out_of_scope_members_are_refused(tmp_path, keys, source, profile, name):
    private, public = keys
    pack = tmp_path / "pack.tar.gz"
    _build(source, pack, private)
    members = _members(pack)
    members[name] = b"payload"
    _repack(pack, members)
    with pytest.raises(DataPackError, match="unsafe path|outside|unexpected member"):
        _import(pack, public, profile)
    assert not (tmp_path / "escape.txt").exists()
    assert not (profile.parent / "escape.txt").exists()


def test_signed_manifest_with_a_traversal_path_is_refused(tmp_path, keys, source, profile):
    """Even a correctly signed manifest cannot name a path outside the data directories."""
    private, public = keys
    key = datapack.load_private_key(private)
    manifest = {
        "kind": datapack.KIND,
        "format": datapack.FORMAT,
        "created": "2026-11-28T00:00:00Z",
        "key_id": datapack.key_id(key.public_key()),
        "label": "",
        "files": [{"path": "mcp/asd-ism/data/../../../x", "sha256": "0" * 64, "size": 1}],
    }
    raw = json.dumps(manifest).encode()
    pack = tmp_path / "pack.tar.gz"
    _repack(pack, {"manifest.json": raw, "manifest.json.sig": key.sign(raw)})
    with pytest.raises(DataPackError, match="unsafe path"):
        _import(pack, public, profile)


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE])
def test_links_and_special_files_are_refused(tmp_path, keys, source, profile, kind):
    private, public = keys
    pack = tmp_path / "pack.tar.gz"
    _build(source, pack, private)
    link = tarfile.TarInfo("files/mcp/asd-ism/data/link.json")
    link.type = kind
    link.linkname = "/etc/passwd"
    _repack(pack, _members(pack), [link])
    with pytest.raises(DataPackError, match="link or special"):
        _import(pack, public, profile)


def test_symlinked_destination_directory_is_refused(tmp_path, keys, source, profile):
    private, public = keys
    pack = tmp_path / "pack.tar.gz"
    _build(source, pack, private)
    outside = tmp_path / "outside"
    outside.mkdir()
    (profile / "intel").mkdir()
    (profile / "intel" / "snapshots").symlink_to(outside)
    with pytest.raises(DataPackError, match="symlink"):
        _import(pack, public, profile)
    assert list(outside.iterdir()) == []


def test_older_pack_needs_allow_older(tmp_path, keys, source, profile):
    private, public = keys
    newer = tmp_path / "newer.tar.gz"
    older = tmp_path / "older.tar.gz"
    _build(source, newer, private, now=WHEN)
    _build(source, older, private, now=datetime(2026, 11, 1, tzinfo=UTC))
    _import(newer, public, profile)
    with pytest.raises(DataPackError, match="before the last imported pack"):
        _import(older, public, profile)
    assert _import(older, public, profile, allow_older=True)["imported"] == 3


def test_missing_public_key_says_where_to_configure_it(tmp_path, keys, source, profile):
    private, _ = keys
    pack = tmp_path / "pack.tar.gz"
    _build(source, pack, private)
    with pytest.raises(DataPackError, match="CYBERAU_DATAPACK_PUBKEY"):
        _import(pack, tmp_path / "absent.pub", profile)


def test_not_a_tarball_is_refused(tmp_path, keys, profile):
    _, public = keys
    bogus = tmp_path / "bogus.tar.gz"
    bogus.write_bytes(b"not a tarball")
    with pytest.raises(DataPackError, match="not a gzip tar"):
        _import(bogus, public, profile)


def test_build_refuses_paths_outside_the_data_directories(tmp_path, keys, source):
    private, _ = keys
    with pytest.raises(DataPackError, match="outside"):
        _build(source, tmp_path / "p.tar.gz", private, paths=["mcp/asd-ism/src/code.py"])
    with pytest.raises(DataPackError, match="unsafe path"):
        _build(source, tmp_path / "p.tar.gz", private, paths=["../etc/passwd"])


def test_public_key_location_is_configurable(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERAU_DATAPACK_PUBKEY", str(tmp_path / "trusted.pub"))
    assert datapack.default_public_key_path() == tmp_path / "trusted.pub"
    monkeypatch.delenv("CYBERAU_DATAPACK_PUBKEY")
    assert datapack.default_public_key_path().name == "datapack-signing.pub"


def test_cli_build_verify_import_and_refusal(tmp_path, keys, source, profile, monkeypatch, capsys):
    private, public = keys
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(profile / "plugin-data" / "cyber-au"))
    pack = tmp_path / "cli.tar.gz"
    assert (
        cli_main(
            ["datapack", "build", "--root", str(source), "--out", str(pack), "--key", str(private)]
        )
        == 0
    )
    assert cli_main(["datapack", "verify", str(pack), "--public-key", str(public)]) == 0
    assert (
        cli_main(
            ["datapack", "import", str(pack), "--public-key", str(public), "--root", str(profile)]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert '"imported": 3' in out

    members = _members(pack)
    members["files/mcp/asd-ism/data/releases.json"] = b"tampered"
    _repack(pack, members)
    code = cli_main(
        ["datapack", "import", str(pack), "--public-key", str(public), "--root", str(profile)]
    )
    assert code == 1
    assert "refused:" in capsys.readouterr().err
