#!/usr/bin/env python3
"""Read and update the pinned Hermes release.

tools/hermes_pin.txt is the single source. ``get`` prints that tag and
``image`` prints the Docker image CI runs (``nousresearch/hermes-agent:<tag>``).
``set`` writes the same tag into:

- distribution.yaml ``hermes_requires`` (lower bound, without the leading v)
- docker/Dockerfile ``HERMES_VERSION``

A new release also moves the immutable pins: the Docker image index digest
(docker/Dockerfile ``HERMES_DIGEST`` and the .devcontainer base image) and the
upstream installer commit and checksum in install/install.sh. Pass them with
``--digest``, ``--commit`` and ``--installer-sha256`` (``resolve`` prints them
for a tag). Without them ``set`` refuses to move the tag, so a tag can never
drift away from its digest.

A missing consumer is an error, and nothing is written until every consumer
can be updated. That keeps the pins from drifting apart.

``set`` never edits files under .github/. Pushing a workflow file needs a token
with the workflows permission, which the data pull request token does not have.
CI reads the image with ``hermes_pin.py image`` at run time instead. ``check``
fails if .github/workflows/ci.yml still hardcodes a different tag.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN_REL = Path("tools/hermes_pin.txt")
DIST_REL = Path("distribution.yaml")
DOCKER_REL = Path("docker/Dockerfile")
CI_REL = Path(".github/workflows/ci.yml")
IMAGE = "nousresearch/hermes-agent"

TAG_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
DIST_RE = re.compile(
    r"^(?P<prefix>[ \t]*hermes_requires:\s*)(?P<q>['\"])>=(?P<ver>[^'\"]+)(?P=q)"
    r"(?P<trail>[ \t]*)$",
    re.MULTILINE,
)
CI_RE = re.compile(
    r"^(?P<prefix>[ \t]*HERMES_IMAGE:\s*nousresearch/hermes-agent:)"
    r"(?P<tag>\S+)(?P<suffix>[ \t]*(?:#.*)?)$",
    re.MULTILINE,
)
DOCKER_RE = re.compile(
    r"^(?P<prefix>[ \t]*(?:ARG|ENV)[ \t]+HERMES_VERSION=)"
    r"(?P<tag>\S+)(?P<suffix>[ \t]*(?:#.*)?)$",
    re.MULTILINE,
)
DEVCONTAINER_REL = Path(".devcontainer/Dockerfile")
INSTALL_REL = Path("install/install.sh")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
DOCKER_DIGEST_RE = re.compile(
    r"^(?P<prefix>ARG[ \t]+HERMES_DIGEST=)sha256:[0-9a-f]{64}(?P<suffix>[ \t]*)$", re.MULTILINE
)
DOCKER_DIGEST_NOTE_RE = re.compile(
    r"^(?P<prefix>#[ \t]*HERMES_DIGEST version:[ \t]*)v\S+$", re.MULTILINE
)
DEVCONTAINER_RE = re.compile(
    r"^(?P<prefix>FROM[ \t]+nousresearch/hermes-agent:)v\S+?@sha256:[0-9a-f]{64}(?P<suffix>.*)$",
    re.MULTILINE,
)
INSTALL_VERSION_RE = re.compile(r"^(?P<prefix>HERMES_PIN_VERSION=)v\S+$", re.MULTILINE)
INSTALL_COMMIT_RE = re.compile(r"^(?P<prefix>HERMES_PIN_COMMIT=)[0-9a-f]{40}$", re.MULTILINE)
INSTALL_SHA_RE = re.compile(r"^(?P<prefix>HERMES_PIN_SHA256=)[0-9a-f]{64}$", re.MULTILINE)
# Comments that name the release next to a digest or installer pin.
DOCKER_COMMENT_RE = re.compile(
    r"(?P<prefix># nousresearch/hermes-agent:)v[0-9]+\.[0-9]+\.[0-9]+(?P<suffix>\. When)"
)
INSTALL_COMMENT_RE = re.compile(r"(?P<prefix># )v[0-9]+\.[0-9]+\.[0-9]+(?P<suffix> tag points to)")
_SECRET = re.compile(r"(?:ghp_|gho_|ghu_|ghs_|github_pat_)[A-Za-z0-9_]+")


class PinError(Exception):
    """The pin could not be read or written."""


def redact(text: str) -> str:
    return _SECRET.sub("[redacted]", text)


def shown(value: str, limit: int = 80) -> str:
    """One redacted line, cut to ``limit`` characters, for an error message."""
    text = redact(value.replace("\n", "\\n").replace("\r", "\\r"))
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def validate_tag(tag: str) -> str:
    if TAG_RE.fullmatch(tag):
        return tag
    raise PinError(f"Refusing tag {shown(tag)!r}. Expected a release like v0.22.2.")


def floor_version(tag: str) -> str:
    validate_tag(tag)
    return tag[1:]


def _inside(root: Path, rel: Path) -> Path:
    base = root.resolve()
    path = (base / rel).resolve()
    if not path.is_relative_to(base):
        raise PinError(f"Refusing to touch a path outside the repository: {rel.as_posix()}")
    return path


def _read(root: Path, rel: Path) -> str:
    path = _inside(root, rel)
    if not path.is_file():
        raise PinError(f"Missing {rel.as_posix()}")
    return path.read_text(encoding="utf-8")


def _replace_exact(text: str, pattern: re.Pattern[str], repl, rel: Path) -> str:
    new, count = pattern.subn(repl, text)
    if count != 1:
        raise PinError(f"{rel.as_posix()} needs exactly one Hermes pin assignment, found {count}")
    return new


def read_pin(root: Path) -> str:
    text = _read(root, PIN_REL)
    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if len(lines) != 1:
        raise PinError("tools/hermes_pin.txt must contain one release tag")
    return validate_tag(lines[0])


def _render_pin(root: Path, tag: str) -> str:
    """Keep the leading comment block so the pin file still explains itself."""
    path = _inside(root, PIN_REL)
    comments: list[str] = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            if line.strip().startswith("#"):
                comments.append(line)
                continue
            break
    return "\n".join([*comments, tag]) + "\n"


def _sub(pattern: re.Pattern[str], value: str):
    def repl(match: re.Match[str]) -> str:
        return f"{match.group('prefix')}{value}{match.groupdict().get('suffix') or ''}"

    return repl


def _apply_immutable(
    root: Path,
    planned: dict[Path, str],
    tag: str,
    digest: str,
    commit: str,
    installer_sha256: str,
) -> None:
    """Move the image digest and installer pins to ``tag`` inside ``planned``."""
    if not DIGEST_RE.fullmatch(digest):
        raise PinError(f"Refusing digest {shown(digest)!r}. Expected sha256:<64 hex>.")
    if not COMMIT_RE.fullmatch(commit):
        raise PinError(f"Refusing commit {shown(commit)!r}. Expected 40 hex characters.")
    if not SHA256_RE.fullmatch(installer_sha256):
        raise PinError(f"Refusing checksum {shown(installer_sha256)!r}. Expected 64 hex.")

    text = planned[DOCKER_REL]
    if "HERMES_DIGEST=" in text:
        text = _replace_exact(text, DOCKER_DIGEST_RE, _sub(DOCKER_DIGEST_RE, digest), DOCKER_REL)
        text = DOCKER_DIGEST_NOTE_RE.sub(_sub(DOCKER_DIGEST_NOTE_RE, tag), text)
        text = DOCKER_COMMENT_RE.sub(_sub(DOCKER_COMMENT_RE, tag), text)
        planned[DOCKER_REL] = text

    dev = _inside(root, DEVCONTAINER_REL)
    if dev.is_file():
        text = dev.read_text(encoding="utf-8")
        if "@sha256:" in text:
            planned[DEVCONTAINER_REL] = _replace_exact(
                text, DEVCONTAINER_RE, _sub(DEVCONTAINER_RE, f"{tag}@{digest}"), DEVCONTAINER_REL
            )

    install = _inside(root, INSTALL_REL)
    if install.is_file():
        text = install.read_text(encoding="utf-8")
        if "HERMES_PIN_COMMIT=" in text:
            for pattern, value in (
                (INSTALL_VERSION_RE, tag),
                (INSTALL_COMMIT_RE, commit),
                (INSTALL_SHA_RE, installer_sha256),
            ):
                text = _replace_exact(text, pattern, _sub(pattern, value), INSTALL_REL)
            text = INSTALL_COMMENT_RE.sub(_sub(INSTALL_COMMENT_RE, tag), text)
            planned[INSTALL_REL] = text


def _plan(root: Path, tag: str) -> list[tuple[Path, str]]:
    version = floor_version(tag)
    planned: list[tuple[Path, str]] = [(PIN_REL, _render_pin(root, tag))]

    def dist_repl(match: re.Match[str]) -> str:
        quote = match.group("q")
        return f"{match.group('prefix')}{quote}>={version}{quote}{match.group('trail')}"

    planned.append((DIST_REL, _replace_exact(_read(root, DIST_REL), DIST_RE, dist_repl, DIST_REL)))

    def docker_repl(match: re.Match[str]) -> str:
        return f"{match.group('prefix')}{tag}{match.group('suffix') or ''}"

    planned.append(
        (
            DOCKER_REL,
            _replace_exact(_read(root, DOCKER_REL), DOCKER_RE, docker_repl, DOCKER_REL),
        )
    )

    return planned


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(text, encoding="utf-8", newline="\n")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def image(root: Path) -> str:
    return f"{IMAGE}:{read_pin(root)}"


def check_ci(root: Path) -> None:
    """Refuse a ci.yml that hardcodes a Hermes tag other than the pin."""
    path = _inside(root, CI_REL)
    if not path.is_file():
        return
    tag = read_pin(root)
    for match in CI_RE.finditer(path.read_text(encoding="utf-8")):
        if match.group("tag") != tag:
            raise PinError(
                f"{CI_REL.as_posix()} hardcodes HERMES_IMAGE {shown(match.group('tag'))}, "
                f"but the pin is {tag}. Read it with tools/hermes_pin.py image instead."
            )


def set_pin(
    root: Path,
    tag: str,
    *,
    digest: str | None = None,
    commit: str | None = None,
    installer_sha256: str | None = None,
) -> None:
    """Write ``tag`` to the pin file and every consumer. All writes happen, or none.

    ``digest``, ``commit`` and ``installer_sha256`` move the image digest and the
    installer pins in the same write. They are required when the tag changes and
    any of those pins exist.
    """
    release = validate_tag(tag)
    immutable = (digest, commit, installer_sha256)
    if any(immutable) and not all(immutable):
        raise PinError("Pass --digest, --commit and --installer-sha256 together.")
    if release != read_pin(root) and not all(immutable):
        # Changing a tag alone would leave the image digest or installer commit
        # on the old release. These pins must be reviewed and changed together.
        for rel, marker in (
            (DOCKER_REL, "HERMES_DIGEST="),
            (DEVCONTAINER_REL, "@sha256:"),
            (INSTALL_REL, "HERMES_PIN_COMMIT="),
        ):
            path = _inside(root, rel)
            if path.is_file() and marker in path.read_text(encoding="utf-8"):
                raise PinError(
                    f"Hermes upgrade requires a manual pin update: {rel} pins a digest or "
                    "installer commit. Pass --digest, --commit and --installer-sha256 "
                    "(see tools/hermes_pin.py resolve) so every pin moves together."
                )
    planned = dict(_plan(root, release))
    if all(immutable):
        _apply_immutable(root, planned, release, digest, commit, installer_sha256)
    for rel, text in planned.items():
        _atomic_write(_inside(root, rel), text)


def _http_get(url: str, headers: dict[str, str] | None = None, *, head: bool = False):
    import urllib.request

    request = urllib.request.Request(url, headers=headers or {}, method="HEAD" if head else "GET")
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 (fixed hosts)
        return response.headers, (b"" if head else response.read())


def resolve(tag: str, *, get=_http_get) -> dict[str, str]:
    """Look up the image digest, commit and installer checksum for a release tag.

    Reads three fixed public hosts: api.github.com, raw.githubusercontent.com and
    Docker Hub. ``GH_TOKEN`` or ``GITHUB_TOKEN``, when set, avoids the anonymous
    GitHub rate limit.
    """
    import hashlib
    import json
    import os

    release = validate_tag(tag)
    gh_headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        gh_headers["Authorization"] = f"Bearer {token}"
    _, body = get(
        f"https://api.github.com/repos/NousResearch/hermes-agent/commits/{release}", gh_headers
    )
    commit = str(json.loads(body)["sha"])
    if not COMMIT_RE.fullmatch(commit):
        raise PinError("GitHub returned an unexpected commit id")
    _, script = get(
        f"https://raw.githubusercontent.com/NousResearch/hermes-agent/{commit}/scripts/install.sh"
    )
    installer_sha256 = hashlib.sha256(script).hexdigest()
    _, body = get(
        f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{IMAGE}:pull"
    )
    registry_token = str(json.loads(body)["token"])
    headers, _ = get(
        f"https://registry-1.docker.io/v2/{IMAGE}/manifests/{release}",
        {
            "Authorization": f"Bearer {registry_token}",
            "Accept": "application/vnd.oci.image.index.v1+json, "
            "application/vnd.docker.distribution.manifest.list.v2+json",
        },
        head=True,
    )
    digest = str(headers.get("Docker-Content-Digest", ""))
    if not DIGEST_RE.fullmatch(digest):
        raise PinError(f"Docker Hub returned no index digest for {IMAGE}:{release}")
    return {
        "tag": release,
        "digest": digest,
        "commit": commit,
        "installer_sha256": installer_sha256,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read and update the pinned Hermes release.")
    parser.add_argument("--root", type=Path, default=ROOT)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("get", help="Print the pinned release tag")
    sub.add_parser("image", help="Print the pinned Hermes Docker image")
    sub.add_parser("check", help="Fail if ci.yml hardcodes a different Hermes tag")
    resolve_parser = sub.add_parser(
        "resolve", help="Print the digest, commit and installer checksum for a tag"
    )
    resolve_parser.add_argument("tag")
    resolve_parser.add_argument(
        "--github-output", action="store_true", help="Print key=value lines for GITHUB_OUTPUT"
    )
    set_parser = sub.add_parser("set", help="Write a release tag through every pin")
    set_parser.add_argument("tag")
    set_parser.add_argument("--digest", help="Image index digest, sha256:<hex>")
    set_parser.add_argument("--commit", help="Upstream commit the tag points to")
    set_parser.add_argument("--installer-sha256", help="sha256 of scripts/install.sh at --commit")
    args = parser.parse_args(argv)
    try:
        if args.command == "get":
            print(read_pin(args.root))
            return 0
        if args.command == "image":
            print(image(args.root))
            return 0
        if args.command == "resolve":
            pins = resolve(args.tag)
            for key, value in pins.items():
                print(f"{key}={value}" if args.github_output else f"{key}: {value}")
            return 0
        if args.command == "check":
            check_ci(args.root)
            return 0
        set_pin(
            args.root,
            args.tag,
            digest=args.digest,
            commit=args.commit,
            installer_sha256=args.installer_sha256,
        )
    except (PinError, OSError, KeyError, ValueError) as exc:
        print(redact(str(exc)), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
