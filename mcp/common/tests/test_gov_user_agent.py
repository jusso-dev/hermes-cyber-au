import re
from pathlib import Path

from cyberau_common import GOV_AU_USER_AGENT, USER_AGENT

MCP = Path(__file__).resolve().parents[2]
DROPPED = re.compile(r"https?:|@|github", re.IGNORECASE)


def test_gov_user_agent_avoids_what_gov_au_sites_drop():
    assert GOV_AU_USER_AGENT.startswith("hermes-cyber-au/")
    assert not DROPPED.search(GOV_AU_USER_AGENT)
    assert DROPPED.search(USER_AGENT), "the shared agent keeps its contact URL"


def test_every_gov_au_connector_sends_the_gov_user_agent():
    offenders = []
    for source in sorted(MCP.glob("*/src/*/source.py")):
        text = source.read_text(encoding="utf-8")
        if not re.search(r"https://[a-z0-9.-]+\.gov\.au/", text):
            continue
        if "GOV_AU_USER_AGENT" not in text:
            offenders.append(str(source.relative_to(MCP)))
    assert offenders == []
