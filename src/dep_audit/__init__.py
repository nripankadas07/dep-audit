"""dep-audit — Python dependency vulnerability scanner using OSV.dev."""

from __future__ import annotations

from .core import DepAuditError, scan_requirements

__all__ = ["DepAuditError", "scan_requirements"]
__version__ = "0.1.0"
