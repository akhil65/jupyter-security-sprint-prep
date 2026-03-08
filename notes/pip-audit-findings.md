# pip-audit Dependency Audit Findings

**Tool:** pip-audit 2.10.0
**Scan date:** 2026-03-08
**Repos audited:** jupyter_server (33f5e29), jupyterhub (48c21eb)
**Raw output:** `scans/pip-audit/jupyter_server.json`, `scans/pip-audit/jupyterhub.json`

> ⚠️ **Network Note:** The pip-audit vulnerability database lookup (osv.dev / PyPI Safety DB)
> requires outbound HTTPS access, which was unavailable during this prep session. The dependency
> lists have been extracted and staged — **run `scans/pip-audit/run-pip-audit.sh` on sprint day
> to populate actual CVE results.**

---

## jupyter_server — Dependency Inventory

Extracted from `repos/jupyter_server/pyproject.toml` (required dependencies only):

| Package | Minimum Version | Notes |
|---------|----------------|-------|
| anyio | >=3.1.0 | Async I/O compatibility layer |
| argon2-cffi | >=21.1 | Password hashing — critical for auth |
| jinja2 | >=3.0.3 | Template engine — XSS risk if misconfigured (see bandit B701) |
| jupyter_client | >=7.4.4 | Kernel communication |
| jupyter_core | >=4.12, !=5.0.* | Core Jupyter utilities |
| jupyter_server_terminals | >=0.4.4 | Terminal support |
| nbconvert | >=6.4.4 | Notebook conversion |
| nbformat | >=5.3.0 | Notebook file format |
| packaging | >=22.0 | Version parsing |
| prometheus_client | >=0.9 | Metrics |
| pyzmq | >=24 | ZeroMQ bindings — kernel comms |
| Send2Trash | >=1.8.2 | Safe file deletion |
| terminado | >=0.8.3 | Terminal via websocket |
| tornado | >=6.2.0 | HTTP server — keep updated |
| traitlets | >=5.6.0 | Configuration framework |
| websocket-client | >=1.7 | WebSocket client |
| jupyter_events | >=0.11.0 | Event system |

**Security-sensitive packages to prioritize in audit:**
- `argon2-cffi` — directly in the auth path; check for known weaknesses in <21.1
- `tornado` — core HTTP server; any unpatched CVEs here are high impact
- `jinja2` — template XSS; known historical CVEs (e.g., GHSA-h5c8-rqwp-cp95)
- `pyzmq` — deserializes data from kernels; injection risk in older versions

---

## jupyterhub — Dependency Inventory

Extracted from `repos/jupyterhub/requirements.txt`:

| Package | Constraint | Notes |
|---------|-----------|-------|
| alembic | >=1.4 | DB migrations — SQL handling |
| certipy | >=0.1.2 | TLS certificate management |
| idna | (unpinned) | Internationalized domain names |
| jinja2 | >=2.11.0 | Template engine — wide version range, check for old CVEs |
| jupyter_events | (unpinned) | — |
| oauthlib | >=3.0 | OAuth library — auth critical path |
| packaging | (unpinned) | — |
| pamela | >=1.1.0 (non-Windows) | PAM authentication |
| prometheus_client | >=0.5.0 | Metrics |
| pydantic | >=2 | Data validation |
| python-dateutil | (unpinned) | — |
| requests | (unpinned) | HTTP client — should pin for reproducibility |
| SQLAlchemy | >=1.4.1 | ORM — SQL injection mitigations depend on version |
| tornado | >=6.1 | HTTP server |
| traitlets | >=5.4 | Configuration |

**Security-sensitive packages to prioritize in audit:**
- `oauthlib` — central to JupyterHub auth flows; any CVEs here are critical
- `SQLAlchemy` — ORM used throughout; old versions had SQL injection vectors
- `tornado` — HTTP server; all known CVEs should be audited
- `jinja2` — wide range (>=2.11.0) means old vulnerable versions could satisfy this
- `requests` — unpinned; SSRF or TLS verification CVEs are relevant

---

## Packages of Concern (Historical CVEs)

These packages have had notable CVEs in the past and should be checked on sprint day:

| Package | Known CVE History | Recommended Action |
|---------|------------------|--------------------|
| `tornado` | CVE-2023-28370 (open redirect), CVE-2024-49769 (header injection) | Verify >=6.4.2 |
| `jinja2` | CVE-2024-22195 (XSS), CVE-2024-56201 (sandbox escape) | Verify >=3.1.5 |
| `requests` | CVE-2023-32681 (Proxy-Auth header leak) | Verify >=2.31.0 |
| `oauthlib` | CVE-2022-36087 (DoS via crafted token) | Verify >=3.2.1 |
| `SQLAlchemy` | Multiple older SQL injection CVEs in <1.4 | Verify >=1.4.1 (already constrained) |
| `cryptography` | CVE-2023-49083, CVE-2023-38325 | Verify >=41.0.6 |

---

## Sprint Day Instructions

1. Ensure network access to `pypi.org` and `osv.dev`
2. Run: `bash scans/pip-audit/run-pip-audit.sh` from the repo root
3. This overwrites `scans/pip-audit/jupyter_server.json` and `jupyterhub.json` with live CVE data
4. Update this document with actual findings
5. Commit with: `git commit -m "scan: add pip-audit CVE results for jupyter_server and jupyterhub"`
