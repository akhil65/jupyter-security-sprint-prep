# jupyter/security — Repo Context & Policy References

**Repo:** https://github.com/jupyter/security
**Pinned commit:** 84e4d5d (see `repo-versions.md`)
**Role in sprint:** Governance and policy reference — not an application to scan, but the authoritative source for Jupyter's security disclosure process and hardening guidance.

---

## Key Documents

### 1. `vulnerability-handling.md`
The primary policy doc for how Jupyter projects handle reported vulnerabilities. Covers:
- Disclosure timeline expectations (acknowledgement within 7 days, patch within 90 days)
- How to report: `security@ipython.org` for historical issues; individual project security advisories via GitHub
- How maintainers triage and escalate across sub-projects
- Coordination with downstream distributors (conda-forge, PyPI, Docker Hub)

**Sprint relevance:** When the `appsec_sprint_evaluator` generates Draft PRs for findings in `jupyter_server` or `jupyterhub`, the remediation notes should reference this policy so maintainers know the expected response timeline and process.

---

### 2. `SingleServer.rst`
Security hardening guide specifically for single-user Jupyter Server deployments. Covers:
- Token-based authentication configuration
- HTTPS / TLS setup
- `--no-browser` and binding recommendations
- Password hashing best practices

**Sprint relevance:** The `jupyter_sec_firewall` extension targets exactly this deployment scenario. The hardening steps in `SingleServer.rst` are complementary to the firewall — they reduce the attack surface at the network/auth layer while the firewall operates at the kernel execution layer. The architecture explainer (`output/architecture-explainer.html`) and any sprint documentation should cross-reference this guide.

---

### 3. `security_manager_faq.md`
FAQ covering the `SecurityManager` API introduced in Jupyter Server, which allows custom authentication backends. Addresses:
- How `SecurityManager` differs from token auth
- Integration patterns for enterprise SSO
- Common misconfiguration pitfalls

**Sprint relevance:** The `jupyter_sec_firewall` extension hooks into the WebSocket channel layer downstream of authentication. Understanding `SecurityManager` is important for sprint attendees who may want to combine the firewall with custom auth backends — the FAQ clarifies the boundary between auth (SecurityManager's job) and execution policy (the firewall's job).

---

## Bandit Scan Results

See `notes/bandit-findings.md` → section "jupyter/security — tools/ Directory Scan" for the 18 findings from scanning `repos/security/tools/`. The 3 actionable MEDIUM findings are B113 (HTTP request without timeout) in the `tide` vulnerability-tracking tool.

---

## What Is NOT in This Repo

The `jupyter/security` repo does **not** contain:
- Application source code (no Flask/Django app, no kernel logic)
- Dependency manifests that pip-audit would scan
- Terraform or IaC files
- Docker images

This means pip-audit, semgrep, and IaC scanners have nothing to run against it — bandit on `tools/` is the only relevant scan, and its surface is intentionally minimal.
