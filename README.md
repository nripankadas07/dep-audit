# dep-audit

Lightweight Python dependency vulnerability scanner. Reads a `requirements.txt` and queries the [OSV.dev](https://osv.dev) database for known vulnerabilities, returning structured `Finding` records or formatted CLI output.

## Install

```bash
pip install dep-audit
```

Requires Python 3.10+. Uses `requests` for OSV transport (pluggable via the `fetcher` argument for testing).

## CLI usage

```bash
dep-audit requirements.txt
```

Exits non-zero if any findings are present.

## Library usage

```python
from dep_audit import scan_requirements

findings = scan_requirements([
    "requests==2.20.0",
    "django==2.2.0",
])
for f in findings:
    print(f.package, f.version, f.vuln_id, f.summary)
```

## API

### `scan_requirements(requirements, *, fetcher=None) -> list[Finding]`
Scan an iterable of requirement lines. Only `name==version` pinned forms are scanned. The optional `fetcher` lets you stub out the OSV API for tests.

### `Finding`
Frozen dataclass: `package`, `version`, `vuln_id`, `summary`, `severity`.

### `DepAuditError`
Raised on transport or input errors.

## License

MIT
