"""dep-audit — query OSV.dev for known vulnerabilities in Python dependencies."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Mapping, Optional

__all__ = ["DepAuditError", "Finding", "scan_requirements"]
__version__ = "0.1.0"

_OSV_API = "https://api.osv.dev/v1/query"
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:[\[<>=!~].*?)?\s*([0-9][0-9A-Za-z.+!-]*)?\s*(?:#.*)?$")


class DepAuditError(Exception):
    """Raised on input or transport errors."""


@dataclass(frozen=True)
class Finding:
    package: str
    version: str
    vuln_id: str
    summary: str
    severity: Optional[str] = None


def _parse_requirement(line: str) -> Optional[tuple]:
    """Parse a single pinned requirement line. Returns (package, version) or None."""
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return None
    # Look for ==<version>
    m = re.match(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([0-9][0-9A-Za-z.+!-]*)", line)
    if m:
        return (m.group(1), m.group(2))
    return None


def scan_requirements(
    requirements: Iterable[str],
    *,
    fetcher=None,
) -> List[Finding]:
    """Scan an iterable of requirement strings and return all OSV findings.

    Args:
        requirements: lines from a requirements.txt-style file.
        fetcher: optional callable(payload) -> dict for testing/customisation.
            Defaults to a thin wrapper over requests.post.

    Returns:
        List of Finding records, one per matched vulnerability.
    """
    if fetcher is None:
        try:
            import requests
        except ImportError as e:
            raise DepAuditError("install dep-audit[default] for requests transport") from e
        def _default_fetch(payload):
            r = requests.post(_OSV_API, json=payload, timeout=30)
            r.raise_for_status()
            return r.json()
        fetcher = _default_fetch
    findings: List[Finding] = []
    for line in requirements:
        if not isinstance(line, str):
            raise DepAuditError(f"requirement must be str, got {type(line).__name__}")
        parsed = _parse_requirement(line)
        if parsed is None:
            continue
        pkg, ver = parsed
        try:
            data = fetcher({
                "package": {"name": pkg, "ecosystem": "PyPI"},
                "version": ver,
            })
        except Exception as e:
            raise DepAuditError(f"OSV query failed for {pkg}=={ver}: {e}") from e
        for vuln in data.get("vulns", []) or []:
            severity = None
            sev = vuln.get("severity") or []
            if sev and isinstance(sev, list) and sev[0].get("score"):
                severity = sev[0]["score"]
            findings.append(Finding(
                package=pkg, version=ver,
                vuln_id=vuln.get("id", "?"),
                summary=(vuln.get("summary") or vuln.get("details", "")).split("\n")[0][:200],
                severity=severity,
            ))
    return findings
