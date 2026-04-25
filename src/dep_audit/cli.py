"""dep-audit CLI entry point."""
from __future__ import annotations

import sys
from pathlib import Path

from .core import DepAuditError, scan_requirements


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else list(argv)
    if not args or args[0] in ("-h", "--help"):
        print("usage: dep-audit <requirements.txt>", file=sys.stderr)
        return 2
    path = Path(args[0])
    if not path.exists():
        print(f"file not found: {path}", file=sys.stderr)
        return 2
    try:
        findings = scan_requirements(path.read_text().splitlines())
    except DepAuditError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if not findings:
        print("no known vulnerabilities found")
        return 0
    for f in findings:
        sev = f" [{f.severity}]" if f.severity else ""
        print(f"{f.package}=={f.version} {f.vuln_id}{sev}: {f.summary}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
