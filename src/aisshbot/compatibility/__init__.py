"""Legacy adapters kept during the Agent migration."""

from .legacy_router import legacy_plan
from .legacy_tools import LegacyToolAdapter

__all__ = ["LegacyToolAdapter", "legacy_plan"]
