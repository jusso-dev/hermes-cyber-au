"""Shared names for the organisation-intelligence slice."""

BANKS = ("org", "intel", "lessons")

ROLES = ("watcher", "analyst", "skeptic", "briefer", "librarian")

# Analyst, skeptic and briefer may recall. They must not retain.
READ_ONLY_ROLES = ("analyst", "skeptic", "briefer")

CONNECTOR_KEYS = (
    "ABUSECH_AUTH_KEY",
    "NVD_API_KEY",
    "OTX_API_KEY",
    "CLOUDFLARE_RADAR_API_TOKEN",
    "GREYNOISE_API_KEY",
)

# Who may append which handoff action. The librarian is not in this chain.
HANDOFF_ACTOR = {
    "post": "watcher",
    "claim": "analyst",
    "answer": "skeptic",
    "draft": "briefer",
}

TLP_MARKINGS = ("CLEAR", "GREEN", "AMBER", "RED")

OVERLAY_FLAGS = {
    "watcher": {
        "holds_connector_keys": True,
        "hindsight_read_only": False,
        "may_deliver_to_owner": False,
    },
    "analyst": {
        "holds_connector_keys": False,
        "hindsight_read_only": True,
        "may_deliver_to_owner": False,
    },
    "skeptic": {
        "holds_connector_keys": False,
        "hindsight_read_only": True,
        "may_deliver_to_owner": False,
    },
    "briefer": {
        "holds_connector_keys": False,
        "hindsight_read_only": True,
        "may_deliver_to_owner": True,
    },
    "librarian": {
        "holds_connector_keys": False,
        "hindsight_read_only": False,
        "may_deliver_to_owner": False,
    },
}
