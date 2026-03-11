# Semgrep Findings

**Tool:** semgrep (p/owasp-top-ten, p/python, p/security-audit)
**Scan date:** 2026-03-08
**Repos scanned:** jupyter_server (33f5e29), jupyterhub (48c21eb)
**Raw results:** `scans/semgrep/<repo>_combined.json`

---

## Summary

| Repo | Findings | Errors |
|------|---------|--------|
| jupyter_server | 13 | 6 |
| jupyterhub | 53 | 9 |

All findings are severity WARNING except one ERROR in jupyterhub (Dockerfile missing USER). The errors are semgrep parse failures on non-Python files (ignored safely).

---

## jupyter_server — 13 Findings

### XSS / Template Injection (11 findings)

These are the most significant cluster. The HTML templates use Jinja2 variables in unsafe ways:

| Rule | Count | Locations |
|------|-------|-----------|
| `unquoted-attribute-var` | 6 | `examples/…/page.html:6`, `templates/page.html:9,11,12,13` |
| `var-in-href` | 3 | `templates/browser-open.html:14`, `templates/logout.html:26`, `templates/page.html:37` |
| `template-unescaped-with-safe` | 2 | `templates/login.html:18,88` |

**What this means:** Template variables are injected into HTML attributes without quoting, into `href` values, and with the `| safe` filter that explicitly disables escaping on the login page. If any of these variables can be influenced by user input or URL parameters, XSS is possible. The login template is the highest-risk location.

### Jinja2 Autoescape Disabled (1 finding)

| Location | Issue |
|----------|-------|
| `jupyter_server/serverapp.py:383` | Jinja2 `Environment` created without `autoescape=True` |

This is the root cause of the template XSS risk above — autoescaping is off globally, so developers must manually escape or use `| safe` carefully.

### Credential Leak in Logger (1 finding)

| Location | Issue |
|----------|-------|
| `jupyter_server/auth/__main__.py:41` | Logger call containing the string `"password stored in config dir: %s"` |

The password value is being logged. Depending on log level and output destination, this could expose credentials in log files or stdout.

---

## jupyterhub — 53 Findings

### Template XSS (35 findings)

The dominant category — spread across many templates:

| Rule | Count | Key locations |
|------|-------|--------------|
| `template-unescaped-with-safe` | 16 | `login.html`, `admin.html`, `error.html`, `page.html`, `spawn.html`, `token.html`, `accept-share.html` |
| `var-in-href` | 13 | `page.html`, `home.html`, `login.html`, `accept-share.html`, `not_running.html` |
| `unquoted-attribute-var` | 5 | `admin.html`, `page.html` |
| `var-in-script-tag` | 3 | `admin.html:5,6,8` |

**What this means:** The `| safe` filter is used heavily across jupyterhub's templates — 16 occurrences. This intentionally bypasses autoescaping, which is fine when the content is known-safe HTML, but dangerous if user-controlled data ever flows through these variables. The `admin.html` template injecting variables directly into `<script>` tags is particularly high risk.

### Jinja2 Autoescape Disabled (2 findings)

| Location | Issue |
|----------|-------|
| `jupyterhub/app.py:3210` | Jinja2 `Environment` without autoescape |
| `jupyterhub/app.py:3218` | Jinja2 `Environment` without autoescape |

Same root issue as jupyter_server — global autoescape is off.

### Nginx Config: Host Header Injection (5 findings)

| Location | Issue |
|----------|-------|
| `docs/howto/configuration/config-proxy.md:57,84,103,118` | `$http_host` / `$host` used in nginx proxy config examples |

The documentation nginx examples use `$http_host` which is attacker-controlled (comes from the HTTP Host header). If copied verbatim, this could allow Host header injection attacks. Should use `$host` with explicit `server_name` validation instead.

### Dynamic urllib Usage (3 findings)

| Location | Issue |
|----------|-------|
| `docs/source/conf.py:201,210,227` | `urllib.request.urlopen` with dynamic URL value |

urllib supports `file://` scheme — if the URL is user-influenced, this could be abused for local file read. These are in documentation build scripts (low runtime risk) but worth noting.

### exec() Usage (3 findings)

| Location | Issue |
|----------|-------|
| `docs/source/rbac/generate-scope-table.py:41,55` | `exec()` in doc generation script |
| `test_docs.py:20` | `exec()` in test file |

All in non-production code (docs/tests). Lower risk but should be reviewed if any input to `exec()` is externally influenced.

### Dockerfile Missing USER (1 finding — ERROR severity)

| Location | Issue |
|----------|-------|
| `examples/service-fastapi/Dockerfile:13` | No `USER` directive — container runs as root |

The example Dockerfile runs as root. While it's an example, example code gets copied into production. Should add `USER` directive.

### Insecure Flask Cookie (1 finding)

| Location | Issue |
|----------|-------|
| `examples/service-whoami-flask/whoami-flask.py:42` | Flask cookie without `secure`, `httponly`, `samesite` flags |

Example Flask service sets a cookie without security flags. Again an example, but worth fixing as a reference.

---

## Priority Actions for Sprint

| Priority | Finding | Repo | Location |
|----------|---------|------|----------|
| 🔴 High | `template-unescaped-with-safe` in admin.html `<script>` tags | jupyterhub | `share/jupyterhub/templates/admin.html:5,6,8` |
| 🔴 High | `| safe` on login.html — user-facing auth page | jupyter_server | `templates/login.html:18,88` |
| 🔴 High | Jinja2 autoescape=False (root cause for all template XSS) | both | `serverapp.py:383`, `app.py:3210,3218` |
| 🟡 Medium | Credential logged: password path written to logger | jupyter_server | `auth/__main__.py:41` |
| 🟡 Medium | Nginx `$http_host` in proxy docs — Host header injection | jupyterhub | `config-proxy.md` |
| 🟡 Medium | `var-in-href` on login/logout pages | both | multiple templates |
| 🟢 Low | Dockerfile runs as root | jupyterhub | `examples/service-fastapi/Dockerfile` |
| 🟢 Low | Flask cookie missing security flags | jupyterhub | `examples/service-whoami-flask` |
