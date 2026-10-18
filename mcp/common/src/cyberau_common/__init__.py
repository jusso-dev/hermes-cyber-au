"""Shared connector library for hermes-cyber-au."""

__version__ = "0.1.0"

USER_AGENT = f"hermes-cyber-au/{__version__} (+https://github.com/jusso-dev/hermes-cyber-au)"
# Australian government sites (cyber.gov.au, asd.gov.au, protectivesecurity.gov.au
# and others) drop requests without a response when the user agent carries a URL,
# an email address or "github". Connectors that call them send this instead.
GOV_AU_USER_AGENT = f"hermes-cyber-au/{__version__}"
