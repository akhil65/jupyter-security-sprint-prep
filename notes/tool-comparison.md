# Security Tool Comparison: bandit vs pip-audit vs semgrep

**Sprint:** Jupyter Security Tooling Sprint — March 31, 2026
**Tools evaluated against:** jupyter_server, jupyterhub

---

## TL;DR

| Tool | What it finds | When to use | Noise level |
|------|--------------|-------------|-------------|
| **bandit** | Insecure Python code patterns (AST-based) | Every commit, CI gate | High (B101 dominates) |
| **pip-audit** | Known CVEs in declared dependencies | Pre-release, dependency updates | Low — high signal |
| **semgrep** | Custom + community security rules, OWASP | Deep audits, code review | Tunable — medium |

---

## bandit

### What it does
Bandit is a Python-specific AST (Abstract Syntax Tree) scanner that checks for common security anti-patterns in source code. It has a library of ~100 built-in checks organized into test IDs (B1xx–B7xx).

### Strengths
- **Zero configuration needed** — works against any Python codebase out of the box
- **Fast** — scans hundreds of files in seconds
- **Good at structural patterns** — finds `shell=True`, hardcoded secrets, insecure temp file usage, weak crypto, assertion abuse
- **Multiple output formats** — JSON, text, CSV, SARIF for CI integration
- **No network required** — fully offline

### Weaknesses
- **Very noisy on test code** — B101 (assert_used) dominates results in pytest-heavy repos (93% of issues in jupyter_server were B101)
- **No data flow analysis** — can't determine if user input actually reaches a dangerous function
- **False positives on intentional patterns** — e.g., `0.0.0.0` binding is expected behavior for Jupyter, flagged as B104
- **No dependency vulnerability data** — only looks at code, not packages

### Results on Jupyter repos
- jupyter_server: 1,234 total (81 actionable after filtering B101)
- jupyterhub: 2,058 total (183 actionable after filtering B101)
- **Highest value findings:** Jinja2 autoescape=False (XSS, B701), shell=True in proxy.py (cmd injection, B602), SQL string formatting (B608)

### Recommended CI configuration
```ini
# .bandit (place in repo root)
[bandit]
skips = B101
exclude_dirs = tests,docs
```

---

## pip-audit

### What it does
pip-audit queries the OSV (Open Source Vulnerabilities) database and/or PyPI's vulnerability data to check declared dependencies against known CVEs. It resolves the full dependency tree (unless `--no-deps` is used) and reports affected package versions.

### Strengths
- **Directly actionable** — CVEs come with CVSS scores, fix versions, and advisory links
- **Dependency-tree aware** — can catch transitive vulnerabilities (without `--no-deps`)
- **Low noise** — results are almost always genuine vulnerabilities, not style issues
- **Machine-readable output** — JSON format integrates cleanly with GitHub Security Advisories / Dependabot
- **Supports multiple input formats** — requirements.txt, pyproject.toml, environment scan

### Weaknesses
- **Requires network access** — queries osv.dev and pypi.org; fully offline use is not supported
- **Only as good as the database** — zero-days and newly-disclosed CVEs won't appear immediately
- **No code analysis** — won't catch insecure use of a safe library
- **Dependency resolution can fail** — complex version constraints or conflicting deps may cause errors

### Results on Jupyter repos
- jupyter_server: ✅ 0 CVEs
- jupyterhub: ✅ 0 CVEs
- Both repos clean against the OSV database as of scan date (2026-03-08)
- Key packages to watch: tornado (CVE-2023-28370+), jinja2 (CVE-2024-22195), oauthlib (CVE-2022-36087), requests (CVE-2023-32681)

### Recommended use
Run on every `requirements.txt` or `pyproject.toml` change. Add to pre-merge CI:
```bash
pip-audit --requirement requirements.txt --format json --output pip-audit-results.json
```

---

## semgrep

### What it does
Semgrep is a polyglot static analysis engine that matches code patterns using a YAML-based rule language. Unlike bandit (which uses Python AST), semgrep patterns are syntactic and can span multiple lines, track variables, and be written in the same language they analyze. The `p/owasp-top-ten` and `p/python` community rulesets provide hundreds of curated rules.

### Strengths
- **High precision** — rules can express multi-step patterns (e.g., "user input flows into SQL query")
- **Customizable** — teams can write org-specific rules for internal patterns
- **Broad coverage** — OWASP Top 10 ruleset covers A1-A10 including injection, broken auth, IDOR, SSRF
- **SARIF output** — integrates natively with GitHub Code Scanning
- **Taint tracking** — the Pro version can track user-controlled data through function calls
- **Polyglot** — can scan Python, JS, YAML config files in the same run

### Weaknesses
- **Requires network to pull community rulesets** — or pre-downloaded rule files
- **More complex to tune** — suppressing false positives requires `# nosemgrep` annotations or rule exclusions
- **Slower than bandit** — rule matching is more computationally intensive
- **Community rules vary in quality** — some p/python rules have high false positive rates

### Results on Jupyter repos
- jupyter_server: 13 findings (11 XSS/template, 1 Jinja2 autoescape, 1 credential leak)
- jupyterhub: 53 findings (37 template XSS, 5 nginx host header, 3 urllib, 3 exec(), 2 Jinja2 autoescape, 1 Dockerfile root, 1 Flask cookie, 1 bind-all-interfaces)
- Rulesets used: `p/owasp-top-ten`, `p/python`, `p/security-audit`

### Recommended use
Run as a deeper audit tool on PRs touching security-sensitive code (auth, sessions, subprocess, HTTP), rather than on every commit. Use SARIF output for GitHub integration:
```bash
semgrep scan --config p/owasp-top-ten --config p/python \
  --sarif --output semgrep.sarif repos/jupyter_server
```

---

## Comparison Matrix

| Dimension | bandit | pip-audit | semgrep |
|-----------|--------|-----------|---------|
| **Analysis type** | AST pattern matching | Vulnerability DB lookup | Syntactic pattern matching |
| **Target** | Python source code | Declared dependencies | Source code (polyglot) |
| **Network required** | No | Yes | Yes (for rulesets) |
| **Speed** | Fast (< 5s for this repo) | Medium (depends on resolver) | Slower (30s–5min) |
| **False positive rate** | High (B101 dominates) | Low | Medium (tunable) |
| **Customizable rules** | Limited (plugins) | No | Yes (YAML) |
| **CVE data** | No | Yes | Partial (via rules) |
| **Data flow tracking** | No | No | Yes (Pro) |
| **CI suitability** | ✅ Every commit | ✅ Dep changes | ✅ Security-sensitive PRs |
| **SARIF output** | Yes | No | Yes |
| **Key output files** | `scans/bandit/` | `scans/pip-audit/` | `scans/semgrep/` |

---

## Recommended Sprint Workflow

For the March 31 sprint, run tools in this order:

1. **bandit** (already done — offline, fast) → triage HIGH/MEDIUM findings, create GitHub issues
2. **pip-audit** (run first thing on sprint day) → check for CVEs in current deps, patch immediately
3. **semgrep** (run after pip-audit) → deeper OWASP analysis, use findings to guide manual review

For ongoing CI, the recommended stack is:
- **bandit** (with B101 suppressed) on every PR — catches new insecure patterns fast
- **pip-audit** on dependency file changes — low noise, high value
- **semgrep** weekly scheduled scan or on security-tagged PRs — thorough but slower

---

## False Positive Management

| Tool | Primary FP pattern | Mitigation |
|------|--------------------|-----------|
| bandit | B101 in test files | `skips = B101` in `.bandit` config |
| bandit | B104 (`0.0.0.0`) in intentional server configs | `# nosec B104` inline comment |
| bandit | B108 in test temp dirs | Exclude test dirs in `.bandit` |
| semgrep | Overly broad OWASP rules | `# nosemgrep: rule-id` inline, or rule exclusions |
| pip-audit | N/A — very low FP rate | — |
