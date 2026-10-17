"""cyber-au plugin. Registers the doctor command."""

from . import doctor
from .cli import main, register

__all__ = ["doctor", "main", "register"]
