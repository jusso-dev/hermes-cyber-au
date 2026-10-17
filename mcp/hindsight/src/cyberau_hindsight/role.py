"""Which profile role this process runs as, and what that role may do.

CYBERAU_PROFILE_ROLE comes from the environment, so it is one input among
several. A role that is missing or unknown is refused. When Hermes passes
HERMES_HOME and the home carries the marker that `profiles.py` wrote, a
different role in the environment is refused too. The marker is the role the
overlay was applied as.
"""

from __future__ import annotations

import re
from pathlib import Path

from cyberau_common.envelope import untrusted_text
from cyberau_common.secrets import lookup

from cyberau_hindsight.constants import CONFIRM_ROLES, RETAIN_ROLES, ROLES

_OPEN = re.compile(r"<<")
_CLOSE = re.compile(r">>")


class RoleError(Exception):
    """The profile role is missing, unknown, or disagrees with its home."""


def effective_role() -> str:
    role = lookup("CYBERAU_PROFILE_ROLE")
    if role is None or role.strip() not in ROLES:
        raise RoleError("CYBERAU_PROFILE_ROLE is unset or is not a known role")
    role = role.strip()
    home = lookup("HERMES_HOME")
    if home:
        marker = Path(home) / "plugin-data" / "cyber-au" / "profile-role"
        if marker.is_file():
            recorded = marker.read_text(encoding="utf-8").strip()
            if recorded != role:
                raise RoleError(
                    "CYBERAU_PROFILE_ROLE does not match the role this home was set up as"
                )
    return role


def may_retain() -> bool:
    try:
        return effective_role() in RETAIN_ROLES
    except RoleError:
        return False


def may_confirm() -> bool:
    try:
        return effective_role() in CONFIRM_ROLES
    except RoleError:
        return False


def untrusted(text: str, source: str) -> str:
    """Wrap text as data. Text cannot close the wrapper early or open a second one."""
    text = _CLOSE.sub("> >", _OPEN.sub("< <", text))
    return untrusted_text(text, source=source)
