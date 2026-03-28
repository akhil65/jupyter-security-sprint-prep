# Bandit Static Analysis Findings

**Tool:** Bandit 1.9.4
**Scan date:** 2026-03-08
**Repos scanned:** jupyter_server (33f5e29), jupyterhub (48c21eb)
**Raw results:** `scans/bandit/jupyter_server.json`, `scans/bandit/jupyterhub.json`

---

## Summary Table

| Repo           | Total Issues | HIGH | MEDIUM | LOW  |
|----------------|-------------|------|--------|------|
| jupyter_server | 1,234       | 1    | 20     | 1,213|
| jupyterhub     | 2,058       | 7    | 22     | 2,029|

The dominant noise source across both repos is **B101 (assert_used)** — 1,153 in jupyter_server and 1,875 in jupyterhub — which are almost entirely in test files. These are low-severity informational findings and can be filtered out in CI with `-s B101` or a `.bandit` config file.

---

## HIGH Severity Findings

### jupyter_server

| Test ID | Location | Issue |
|---------|----------|-------|
| B701 | `jupyter_server/serverapp.py:383` | Jinja2 autoescape disabled — XSS risk |

**Context:** The Jinja2 `Environment` is initialized without `autoescape=True`. This is a real concern because the server renders user-facing HTML templates. The `select_autoescape()` helper should be used for HTML/XML templates.

---

### jupyterhub

| Test ID | Location | Issue |
|---------|----------|-------|
| B701 | `jupyterhub/app.py:3210` | Jinja2 autoescape disabled — XSS risk |
| B701 | `jupyterhub/app.py:3218` | Jinja2 autoescape disabled — XSS risk |
| B602 | `jupyterhub/proxy.py:757` | `subprocess.Popen(shell=True)` — command injection risk |
| B602 | `jupyterhub/setup.py:105` | `subprocess.Popen(shell=True)` in build script |
| B602 | `jupyterhub/setup.py:158` | `subprocess.Popen(shell=True)` in build script |
| B602 | `jupyterhub/setup.py:196` | `subprocess.Popen(shell=True)` in build script |
| B602 | `jupyterhub/setup.py:203` | `subprocess.Popen(shell=True)` in build script |

**Context on B602:** `shell=True` in `proxy.py` is noteworthy — it's in runtime code that manages the configurable proxy process. If any part of the shell string is user-influenced, this is a command injection vector. The `setup.py` instances are in build tooling and lower risk in practice. Prefer passing a list of arguments to `subprocess.Popen` with `shell=False`.

---

## MEDIUM Severity Findings

### jupyter_server (20 findings)

| Test ID | Count | Description | Example Location |
|---------|-------|-------------|-----------------|
| B108 | 13 | Probable insecure temp file/directory usage | `tests/services/contents/test_fileio.py:175` |
| B104 | 1 | Hardcoded bind to all interfaces (`0.0.0.0`) | `serverapp.py:2359` |
| B608 | 2 | Possible SQL injection via string-based query | `services/sessions/sessionmanager.py:411` |
| B604 | 1 | `shell=True` in `any_other_function` | `gateway/managers.py:765` |
| B113 | 2 | HTTP requests without timeout | `tests/extension/test_launch.py:36` |
| B103 | 1 | Permissive file permissions (`chmod 0o701`) | `tests/services/contents/test_fileio.py:34` |

**Notable:** The **B608** finding in `sessionmanager.py` warrants manual review — string-formatted SQL queries can introduce injection if any parameter comes from user input. The **B104** binding finding in `serverapp.py` is expected behavior for a Jupyter server but should be documented as intentional.

### jupyterhub (22 findings)

| Test ID | Count | Description | Example Location |
|---------|-------|-------------|-----------------|
| B104 | 7 | Hardcoded bind to all interfaces | `examples/bootstrap-script/jupyterhub_config.py:41` |
| B102 | 3 | `exec()` used | `docs/source/rbac/generate-scope-table.py:41` |
| B103 | 3 | Permissive file permissions | `tests/test_app.py:188` |
| B108 | 3 | Insecure temp file/directory | `spawner.py:2190` |
| B608 | 2 | Possible SQL injection in alembic migration | `alembic/versions/99a28a4418e1_user_created.py:32` |
| B310 | 3 | `urllib.request.urlopen` with unvalidated URL | `docs/source/conf.py:201` |
| B113 | 1 | HTTP requests without timeout | `tests/mockservice.py:56` |

**Notable:** The **B108** finding in `spawner.py:2190` is in production code (not tests), meaning temp file handling in the spawner may be insecure. The **B608** in an alembic migration may be a false positive (migration scripts often use literal SQL) but should be verified.

---

## Recommended Actions for Sprint

1. **Immediately review:** `jupyterhub/proxy.py:757` — runtime `shell=True` subprocess. Evaluate whether the command string can be influenced by user/admin input.
2. **Review:** Both Jinja2 `autoescape=False` instances (`jupyter_server/serverapp.py:383`, `jupyterhub/app.py:3210, 3218`). If any template context includes user-supplied data, XSS is possible.
3. **Review:** `jupyter_server/services/sessions/sessionmanager.py:411` — verify SQL query construction is safe.
4. **Review:** `jupyterhub/jupyterhub/spawner.py:2190` — insecure temp file usage in production code.
5. **Filter noise in CI:** Add `.bandit` config to skip B101 (assert_used) in test directories.

---

## Noise Breakdown

The overwhelming majority of findings are B101 (assert_used) in test files — a known benign pattern in pytest-based projects. Filtering these reveals a much smaller actionable set:

| Repo           | Actionable (non-B101) |
|----------------|----------------------|
| jupyter_server | 81                   |
| jupyterhub     | 183                  |

---

## jupyter/security — `tools/` Directory Scan

**Scan date:** 2026-03-27
**Path scanned:** `repos/security/tools/`
**Raw results:** `scans/bandit/security_tools.json`
**Total findings:** 18 (0 HIGH, 3 MEDIUM, 15 LOW)

### MEDIUM Severity (3 findings)

| Test ID | Location | Issue |
|---------|----------|-------|
| B113 | `tools/tide/tide.py:20` | HTTP request without timeout — `requests.get()` call |
| B113 | `tools/tide/tide.py:52` | HTTP request without timeout — `requests.get()` call |
| B113 | `tools/all_repos.py:42` | HTTP request without timeout — `requests.get()` call |

**Context:** All three are B113 (request_without_timeout) in the `tide` tool and `all_repos.py`. These tools query GitHub's API to track vulnerability disclosure status across Jupyter repos. Without a timeout, any network hang will block the process indefinitely — a reliability concern for automated CI/CD use rather than a direct security exploit. Fix: add `timeout=30` (or appropriate value) to each `requests.get()` call.

### LOW Severity (15 findings)

Predominantly B101 (assert_used) in test helpers and B110 (try/except/pass) patterns. No action required.

### Notes

The `jupyter/security` repo is not an application codebase — it contains governance documents and lightweight tooling for coordinating security disclosures across the Jupyter ecosystem. The bandit surface area is intentionally small. The 3 MEDIUM findings are in operational tooling that could run in CI; adding timeouts is a low-effort hardening step.
