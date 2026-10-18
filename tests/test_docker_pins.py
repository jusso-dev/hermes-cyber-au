"""Pins in docker/ and install/install.sh. No network."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "docker" / "Dockerfile"
COMPOSE = ROOT / "docker" / "compose.yaml"
INSTALL = ROOT / "install" / "install.sh"
ENTRYPOINT = ROOT / "docker" / "entrypoint.sh"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def test_every_from_is_pinned_by_digest():
    text = _dockerfile()
    froms = [line for line in text.splitlines() if line.startswith("FROM ")]
    assert froms
    for line in froms:
        image = line.split()[1]
        assert "@" in image, line
        if "${HERMES_DIGEST}" not in image:
            assert DIGEST.search(image), line
    assert re.search(r"^ARG HERMES_DIGEST=sha256:[0-9a-f]{64}$", text, re.MULTILINE)


def test_hermes_digest_matches_hermes_version():
    text = _dockerfile()
    version = re.search(r"^ARG HERMES_VERSION=(\S+)$", text, re.MULTILINE)
    named = re.search(r"^# HERMES_DIGEST version: (\S+)$", text, re.MULTILINE)
    assert version and named
    assert named.group(1) == version.group(1), (
        "HERMES_VERSION changed but HERMES_DIGEST was not updated. Look up the "
        "digest for the new tag and update both lines."
    )


def test_no_script_is_piped_into_a_shell():
    pipe = re.compile(r"\|\s*(?:ba)?sh\b")
    for path in (DOCKERFILE, COMPOSE, ROOT / "docker" / "entrypoint.sh"):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            assert not pipe.search(line), f"{path.name}:{number}: {line}"


def test_compose_image_is_overridable_and_builds_locally_by_default():
    text = COMPOSE.read_text(encoding="utf-8")
    assert "image: ${CYBERAU_IMAGE:-hermes-cyber-au:local}" in text
    assert "dockerfile: docker/Dockerfile" in text
    assert ":0.1.0" not in text


def test_entrypoint_sets_profile_home_for_scratch_plugin_imports():
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert "CYBERAU_HOME=$DEST" in text
    assert "export CYBERAU_HOME" in text


def test_install_sh_pins_the_hermes_installer():
    text = INSTALL.read_text(encoding="utf-8")
    version = re.search(r"^HERMES_PIN_VERSION=(v\d+\.\d+\.\d+)$", text, re.MULTILINE)
    commit = re.search(r"^HERMES_PIN_COMMIT=([0-9a-f]{40})$", text, re.MULTILINE)
    checksum = re.search(r"^HERMES_PIN_SHA256=([0-9a-f]{64})$", text, re.MULTILINE)
    assert version and commit and checksum
    pin = (ROOT / "tools" / "hermes_pin.txt").read_text(encoding="utf-8")
    pinned = [
        line.strip() for line in pin.splitlines() if line.strip() and not line.startswith("#")
    ]
    assert pinned == [version.group(1)], (
        "tools/hermes_pin.txt changed. Update HERMES_PIN_VERSION, HERMES_PIN_COMMIT "
        "and HERMES_PIN_SHA256 in install/install.sh to the new release."
    )
    runner = text.split("run_hermes_installer() {", 1)[1].split("\n}\n", 1)[0]
    assert 'verify_sha256 "$HERMES_SCRIPT_DIR/install.sh" "$HERMES_PIN_SHA256"' in runner
    assert '--commit "$HERMES_PIN_COMMIT"' in runner
