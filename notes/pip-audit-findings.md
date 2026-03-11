# pip-audit Dependency Audit Findings

**Tool:** pip-audit 2.10.0
**Scan date:** 2026-03-08
**Repos audited:** jupyter_server (33f5e29), jupyterhub (48c21eb)
**Raw output:** `scans/pip-audit/jupyter_server.json`, `scans/pip-audit/jupyterhub.json`

---

## Result: No Known Vulnerabilities Found

Both repos came back clean against the OSV vulnerability database.

| Repo | CVEs Found |
|------|-----------|
| jupyter_server | ✅ 0 |
| jupyterhub | ✅ 0 |

This means none of the declared dependencies (at their specified minimum versions) have entries in the OSV / PyPI safety database as of the scan date.

---

## What This Means

A clean pip-audit result is good news but has limits:

- It checks **declared** dependencies only (`--no-deps` flag was used), not the full resolved transitive tree. A transitive dependency could still carry a CVE.
- It reflects the vulnerability database **as of scan date** — new CVEs are disclosed daily.
- It checks for **known** CVEs. Zero-days and unregistered vulnerabilities are not detected.

---

## Packages to Keep Watching

Even with a clean result today, these packages have active CVE histories and should be re-audited whenever they are updated:

| Package | Reason to Watch |
|---------|----------------|
| `tornado` | Core HTTP server; CVE-2023-28370 (open redirect), CVE-2024-49769 fixed in recent releases |
| `jinja2` | Template engine; CVE-2024-22195 (XSS), CVE-2024-56201 (sandbox escape) fixed in >=3.1.5 |
| `oauthlib` | Auth critical path in jupyterhub; CVE-2022-36087 (DoS) fixed in >=3.2.1 |
| `requests` | Unpinned in jupyterhub; CVE-2023-32681 (proxy auth header leak) fixed in >=2.31.0 |
| `cryptography` | CVE-2023-49083, CVE-2023-38325; actively maintained, update frequently |

---

## Recommendation

Re-run pip-audit after any dependency update:

```bash
source venv/bin/activate
bash scans/pip-audit/run-pip-audit.sh
```

For a deeper audit including transitive dependencies, remove the `--no-deps` flag from the script.
