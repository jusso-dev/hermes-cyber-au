"""Signed data packs: refresh shipped snapshots on a machine with no network.

A data pack is a gzip tarball with three kinds of member:

- ``manifest.json``: format, creation time, signing key id and, for every file, its
  destination path, size and SHA-256.
- ``manifest.json.sig``: an Ed25519 signature over the exact ``manifest.json`` bytes.
- ``files/<path>``: the file content. ``<path>`` is relative to the profile home.

``import`` checks the signature against a trusted public key before it writes
anything, then checks every file against the manifest, then moves the files into
place. A pack with a bad or missing signature, an unexpected member, a path that
leaves the allowed directories, a link or device member, or a file whose hash does
not match is refused and nothing is written.

The private signing key stays with the maintainer. It is never committed. The
public key is read from ``--public-key``, else ``CYBERAU_DATAPACK_PUBKEY``, else
``mcp/datapack-signing.pub`` beside the connectors.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from cyberau_common import runtime

FORMAT = 1
KIND = "cyber-au-datapack"
MANIFEST = "manifest.json"
SIGNATURE = "manifest.json.sig"
FILES_PREFIX = "files/"
PUBKEY_ENV = "CYBERAU_DATAPACK_PUBKEY"
PASSPHRASE_ENV = "CYBERAU_DATAPACK_KEY_PASSPHRASE"
DEFAULT_PUBKEY_NAME = "datapack-signing.pub"
STATE_NAME = "datapack-state.json"

MAX_FILES = 5000
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024

# Destinations a pack may write. Shipped connector snapshots and public intel store
# snapshots only. Never code, config, credentials or the store itself.
_ALLOWED = (
    re.compile(r"^mcp/[a-z][a-z0-9-]{0,40}/data/(?:[A-Za-z0-9._-]+/){0,4}[A-Za-z0-9._-]+$"),
    re.compile(r"^intel/snapshots/[A-Za-z0-9._-]+$"),
)
_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")


class DataPackError(Exception):
    """A pack that must not be built or imported. The message says why."""


@dataclass(frozen=True)
class PackFile:
    path: str
    sha256: str
    size: int


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - cryptography is a declared dependency
        raise DataPackError(
            "the cryptography package is not installed. Re-run install/bootstrap.sh."
        ) from exc
    return InvalidSignature, serialization, ed25519


# Keys


def generate_keypair(private_path: Path, public_path: Path) -> str:
    """Write a new Ed25519 key pair. The private key file is mode 600. Returns the key id."""
    _, serialization, ed25519 = _crypto()
    for path in (private_path, public_path):
        if path.exists() or path.is_symlink():
            raise DataPackError(f"{path} already exists. Move it aside first.")
    checkout = _git_checkout_containing(private_path)
    if checkout is not None:
        raise DataPackError(
            f"refusing to write a private key inside the git checkout {checkout}. "
            "Keep it outside every repository."
        )
    key = ed25519.Ed25519PrivateKey.generate()
    passphrase = os.environ.get(PASSPHRASE_ENV, "")
    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        if passphrase
        else serialization.NoEncryption()
    )
    private_bytes = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )
    public_bytes = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(private_bytes)
    public_path.write_bytes(public_bytes)
    return key_id(key.public_key())


def key_id(public_key) -> str:
    """First 16 hex characters of the SHA-256 of the raw public key."""
    _, serialization, _ = _crypto()
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def load_private_key(path: Path):
    _, serialization, ed25519 = _crypto()
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise DataPackError(f"cannot read the signing key {path}: {exc.strerror}") from exc
    passphrase = os.environ.get(PASSPHRASE_ENV, "")
    try:
        key = serialization.load_pem_private_key(
            data, password=passphrase.encode("utf-8") if passphrase else None
        )
    except (TypeError, ValueError) as exc:
        raise DataPackError(
            f"{path} is not a readable PEM private key. If it is encrypted, set {PASSPHRASE_ENV}."
        ) from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise DataPackError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: Path):
    _, serialization, ed25519 = _crypto()
    try:
        data = path.read_bytes()
    except FileNotFoundError as exc:
        raise DataPackError(
            f"no data pack public key at {path}. Pass --public-key or set {PUBKEY_ENV}."
        ) from exc
    except OSError as exc:
        raise DataPackError(f"cannot read the public key {path}: {exc.strerror}") from exc
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError as exc:
        raise DataPackError(f"{path} is not a PEM public key") from exc
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise DataPackError(f"{path} is not an Ed25519 public key")
    return key


def default_public_key_path() -> Path:
    raw = os.environ.get(PUBKEY_ENV, "").strip()
    if raw:
        return Path(raw).expanduser()
    return runtime.MCP_DIR / DEFAULT_PUBKEY_NAME


def default_root() -> Path:
    """The profile home (or checkout) that holds ``mcp/`` and ``intel/``."""
    return runtime.MCP_DIR.parent


# Paths


def check_destination(path: str) -> str:
    """Return ``path`` when a pack may write it, else raise DataPackError."""
    if not isinstance(path, str) or not path:
        raise DataPackError("a manifest entry has no path")
    if "\\" in path or path.startswith("/") or "\x00" in path:
        raise DataPackError(f"unsafe path in data pack: {path!r}")
    parts = PurePosixPath(path).parts
    if any(part in {"", ".", ".."} or not _SEGMENT.match(part) for part in parts):
        raise DataPackError(f"unsafe path in data pack: {path!r}")
    if PurePosixPath(*parts).as_posix() != path:
        raise DataPackError(f"unsafe path in data pack: {path!r}")
    if not any(rule.match(path) for rule in _ALLOWED):
        raise DataPackError(
            f"data pack path {path} is outside mcp/<connector>/data/ and intel/snapshots/"
        )
    return path


def default_sources(root: Path) -> list[str]:
    """Files a pack carries by default: shipped connector data and public store snapshots."""
    found: list[str] = []
    mcp = root / "mcp"
    for data_dir in sorted(mcp.glob("*/data")):
        if not data_dir.is_dir() or data_dir.is_symlink():
            continue
        for file in sorted(data_dir.rglob("*")):
            if file.is_file() and not file.is_symlink():
                found.append(file.relative_to(root).as_posix())
    snapshots = root / "intel" / "snapshots"
    if snapshots.is_dir():
        for file in sorted(snapshots.glob("public-*.sqlite.zst")):
            if file.is_file() and not file.is_symlink():
                found.append(file.relative_to(root).as_posix())
    return found


# Build


def build_pack(
    root: Path,
    out: Path,
    private_key_path: Path,
    *,
    paths: Iterable[str] | None = None,
    now: datetime | None = None,
    label: str = "",
) -> dict:
    """Write a signed pack of ``paths`` (relative to ``root``) to ``out``."""
    root = root.resolve()
    key = load_private_key(private_key_path)
    selected = list(paths) if paths is not None else default_sources(root)
    if not selected:
        raise DataPackError(f"nothing to pack under {root}")
    if len(selected) > MAX_FILES:
        raise DataPackError(f"too many files for one pack ({len(selected)} > {MAX_FILES})")
    entries: list[PackFile] = []
    seen: set[str] = set()
    for rel in selected:
        check_destination(rel)
        if rel in seen:
            raise DataPackError(f"{rel} is listed twice")
        seen.add(rel)
        source = root / rel
        if source.is_symlink() or not source.is_file():
            raise DataPackError(f"{rel} is not a regular file under {root}")
        digest, size = _hash_file(source)
        if size > MAX_FILE_BYTES:
            raise DataPackError(f"{rel} is larger than {MAX_FILE_BYTES} bytes")
        entries.append(PackFile(rel, digest, size))
    created = (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = {
        "kind": KIND,
        "format": FORMAT,
        "created": created,
        "key_id": key_id(key.public_key()),
        "label": label,
        "files": [{"path": e.path, "sha256": e.sha256, "size": e.size} for e in entries],
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    signature = key.sign(manifest_bytes)
    out.parent.mkdir(parents=True, exist_ok=True)
    partial = out.with_name(out.name + ".partial")
    with tarfile.open(partial, "w:gz") as archive:
        _add_bytes(archive, MANIFEST, manifest_bytes)
        _add_bytes(archive, SIGNATURE, signature)
        for entry in entries:
            info = _info(FILES_PREFIX + entry.path, entry.size)
            with (root / entry.path).open("rb") as handle:
                archive.addfile(info, handle)
    os.replace(partial, out)
    return {
        "path": str(out),
        "files": len(entries),
        "created": created,
        "key_id": manifest["key_id"],
    }


def _info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mtime = 0
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def _add_bytes(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    archive.addfile(_info(name, len(payload)), io.BytesIO(payload))


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


# Verify and import


def verify_pack(pack: Path, public_key_path: Path) -> dict:
    """Check the signature and every file. Writes nothing. Returns the manifest."""
    with tempfile.TemporaryDirectory(prefix="cyberau-datapack-") as tmp:
        manifest, _ = _verified_staging(pack, public_key_path, Path(tmp))
    return manifest


def import_pack(
    pack: Path,
    public_key_path: Path,
    *,
    root: Path,
    state_path: Path | None = None,
    allow_older: bool = False,
) -> dict:
    """Verify ``pack`` and move its files under ``root``. All or nothing."""
    root = root.resolve()
    if not root.is_dir():
        raise DataPackError(f"{root} is not a directory")
    state = state_path or runtime.profile_data_dir() / STATE_NAME
    staging_parent = root / ".datapack-staging"
    _refuse_symlink(staging_parent)
    staging_parent.mkdir(mode=0o700, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="import-", dir=staging_parent))
    try:
        manifest, staged = _verified_staging(pack, public_key_path, staging)
        previous = _last_created(state)
        if previous and manifest["created"] < previous and not allow_older:
            raise DataPackError(
                f"this pack was created {manifest['created']}, before the last imported pack "
                f"({previous}). Pass --allow-older to import it anyway."
            )
        targets = [
            (staged[entry["path"]], _target(root, entry["path"])) for entry in manifest["files"]
        ]
        for source, target in targets:
            target.parent.mkdir(parents=True, exist_ok=True)
            _refuse_symlink(target)
            os.replace(source, target)
        _write_state(state, manifest)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
        try:
            staging_parent.rmdir()
        except OSError:
            pass
    return {
        "imported": len(manifest["files"]),
        "created": manifest["created"],
        "key_id": manifest["key_id"],
        "root": str(root),
    }


def _verified_staging(pack: Path, public_key_path: Path, staging: Path) -> tuple[dict, dict]:
    invalid_signature, _, _ = _crypto()
    public_key = load_public_key(public_key_path)
    if pack.is_symlink() or not pack.is_file():
        raise DataPackError(f"{pack} is not a file")
    try:
        archive = tarfile.open(pack, "r:gz")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise DataPackError(f"{pack} is not a gzip tar data pack") from exc
    with archive:
        members = _checked_members(archive)
        if MANIFEST not in members:
            raise DataPackError("the pack has no manifest.json. It is not a signed data pack.")
        if SIGNATURE not in members:
            raise DataPackError("the pack is not signed (manifest.json.sig is missing)")
        manifest_bytes = _read_small(archive, members[MANIFEST], MAX_MANIFEST_BYTES)
        signature = _read_small(archive, members[SIGNATURE], 1024)
        try:
            public_key.verify(signature, manifest_bytes)
        except invalid_signature as exc:
            raise DataPackError(
                "the signature does not match the trusted public key. "
                "The pack was changed after signing or was signed by a different key."
            ) from exc
        manifest = _parse_manifest(manifest_bytes)
        if manifest["key_id"] != key_id(public_key):
            raise DataPackError("the manifest names a different signing key")
        expected = {entry["path"]: entry for entry in manifest["files"]}
        carried = {
            name[len(FILES_PREFIX) :]: info
            for name, info in members.items()
            if name.startswith(FILES_PREFIX)
        }
        extra = sorted(set(carried) - set(expected))
        if extra:
            raise DataPackError(f"the pack carries a file the manifest does not list: {extra[0]}")
        missing = sorted(set(expected) - set(carried))
        if missing:
            raise DataPackError(f"the pack is missing {missing[0]}")
        staged: dict[str, Path] = {}
        for index, (path, entry) in enumerate(sorted(expected.items())):
            info = carried[path]
            if info.size != entry["size"]:
                raise DataPackError(f"{path} size does not match the manifest")
            dest = staging / f"{index:05d}"
            digest = hashlib.sha256()
            handle = archive.extractfile(info)
            if handle is None:
                raise DataPackError(f"{path} is not a regular file")
            with handle, dest.open("wb") as out:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
                    out.write(block)
            if digest.hexdigest() != entry["sha256"]:
                raise DataPackError(f"{path} does not match its SHA-256 in the manifest")
            staged[path] = dest
    return manifest, staged


def _checked_members(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    members: dict[str, tarfile.TarInfo] = {}
    total = 0
    for info in archive:
        name = info.name
        if len(members) >= MAX_FILES + 2:
            raise DataPackError("the pack has too many members")
        if name.startswith("/") or "\\" in name or "\x00" in name:
            raise DataPackError(f"unsafe path in data pack: {name!r}")
        parts = PurePosixPath(name).parts
        if any(part in {"..", ""} for part in parts):
            raise DataPackError(f"unsafe path in data pack: {name!r}")
        if info.isdir():
            continue
        if not info.isfile():
            raise DataPackError(f"the pack holds a link or special file: {name!r}")
        if name in members:
            raise DataPackError(f"the pack lists {name} twice")
        if name not in {MANIFEST, SIGNATURE}:
            if not name.startswith(FILES_PREFIX):
                raise DataPackError(f"unexpected member in data pack: {name!r}")
            check_destination(name[len(FILES_PREFIX) :])
        if info.size > MAX_FILE_BYTES:
            raise DataPackError(f"{name} is too large")
        total += info.size
        if total > MAX_TOTAL_BYTES:
            raise DataPackError("the pack is too large")
        members[name] = info
    return members


def _read_small(archive: tarfile.TarFile, info: tarfile.TarInfo, limit: int) -> bytes:
    if info.size > limit:
        raise DataPackError(f"{info.name} is too large")
    handle = archive.extractfile(info)
    if handle is None:
        raise DataPackError(f"{info.name} is not a regular file")
    with handle:
        return handle.read(limit + 1)[:limit]


def _parse_manifest(raw: bytes) -> dict:
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DataPackError("manifest.json is not valid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("kind") != KIND:
        raise DataPackError("manifest.json is not a cyber-au data pack manifest")
    if manifest.get("format") != FORMAT:
        raise DataPackError(f"unsupported data pack format {manifest.get('format')!r}")
    created = manifest.get("created")
    if not isinstance(created, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", created
    ):
        raise DataPackError("manifest.json has no valid created time")
    if not isinstance(manifest.get("key_id"), str):
        raise DataPackError("manifest.json has no key id")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise DataPackError("manifest.json lists no files")
    seen: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise DataPackError("a manifest entry is not an object")
        path = check_destination(entry.get("path"))
        if path in seen:
            raise DataPackError(f"{path} is listed twice")
        seen.add(path)
        if not isinstance(entry.get("sha256"), str) or not re.fullmatch(
            r"[0-9a-f]{64}", entry["sha256"]
        ):
            raise DataPackError(f"{path} has no valid SHA-256")
        size = entry.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= MAX_FILE_BYTES:
            raise DataPackError(f"{path} has no valid size")
    return manifest


def _target(root: Path, rel: str) -> Path:
    target = root / rel
    current = root
    for part in PurePosixPath(rel).parts[:-1]:
        current = current / part
        _refuse_symlink(current)
    if not target.resolve().is_relative_to(root):
        raise DataPackError(f"{rel} resolves outside {root}")
    return target


def _refuse_symlink(path: Path) -> None:
    if path.is_symlink():
        raise DataPackError(f"{path} is a symlink. Refusing to write through it.")


def _last_created(state: Path) -> str:
    try:
        loaded = json.loads(state.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    value = loaded.get("created") if isinstance(loaded, dict) else None
    return value if isinstance(value, str) else ""


def _write_state(state: Path, manifest: dict) -> None:
    state.parent.mkdir(parents=True, exist_ok=True)
    _refuse_symlink(state)
    payload = {
        "created": manifest["created"],
        "key_id": manifest["key_id"],
        "label": manifest.get("label", ""),
        "files": len(manifest["files"]),
        "imported_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    temporary = state.with_name(state.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, state)


def _git_checkout_containing(path: Path) -> Path | None:
    for parent in path.expanduser().absolute().parents:
        if (parent / ".git").exists():
            return parent
    return None


# Command line


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cyberau-mcp datapack",
        description="Build, verify and import signed data packs for offline profiles.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="Create an Ed25519 signing key pair (maintainer only)")
    keygen.add_argument("--private", required=True, type=Path, help="Private key path (mode 600)")
    keygen.add_argument("--public", required=True, type=Path, help="Public key path")

    build = sub.add_parser("build", help="Write a signed data pack")
    build.add_argument("--out", required=True, type=Path)
    build.add_argument("--key", required=True, type=Path, help="Ed25519 private key (PEM)")
    build.add_argument("--root", type=Path, default=None, help="Checkout or profile home")
    build.add_argument(
        "--include",
        action="append",
        default=None,
        help="Path relative to --root. Repeat. Default: mcp/*/data and intel/snapshots",
    )
    build.add_argument("--label", default="")

    for name, text in (
        ("verify", "Check a pack's signature and files without writing"),
        ("import", "Verify a pack and install its files into the profile"),
    ):
        command = sub.add_parser(name, help=text)
        command.add_argument("pack", type=Path)
        command.add_argument(
            "--public-key",
            type=Path,
            default=None,
            help=f"Trusted public key. Default: {PUBKEY_ENV}, else mcp/{DEFAULT_PUBKEY_NAME}",
        )
        if name == "import":
            command.add_argument("--root", type=Path, default=None, help="Profile home")
            command.add_argument(
                "--allow-older",
                action="store_true",
                help="Accept a pack created before the last imported one",
            )

    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            kid = generate_keypair(args.private, args.public)
            result = {"key_id": kid, "private": str(args.private), "public": str(args.public)}
        elif args.command == "build":
            result = build_pack(
                (args.root or default_root()),
                args.out,
                args.key,
                paths=args.include,
                label=args.label,
            )
        elif args.command == "verify":
            manifest = verify_pack(args.pack, args.public_key or default_public_key_path())
            result = {
                "verified": True,
                "created": manifest["created"],
                "key_id": manifest["key_id"],
                "files": len(manifest["files"]),
            }
        else:
            result = import_pack(
                args.pack,
                args.public_key or default_public_key_path(),
                root=args.root or default_root(),
                allow_older=args.allow_older,
            )
    except DataPackError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0
