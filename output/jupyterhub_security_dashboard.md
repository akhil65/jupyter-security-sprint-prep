# Security Findings Dashboard: jupyterhub

## Overview
This report aggregates findings across SAST, SCA, Secrets, IaC, DAST, and AI-SPM for the target repository.

### Risk Breakdown
- **SAST:** 82
- **SCA:** 0
- **SECRETS:** 0
- **IAC:** 0
- **DAST:** 0
- **AI-SPM:** 0

## Actionable True Positives (82)

### 1. [MEDIUM] SAST (bandit): B310
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/docs/source/conf.py:201`

**Description:** [B310] blacklist: Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**AI Suggested Fix:** Manual review required.

---
### 2. [MEDIUM] SAST (bandit): B310
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/docs/source/conf.py:210`

**Description:** [B310] blacklist: Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**AI Suggested Fix:** Manual review required.

---
### 3. [MEDIUM] SAST (bandit): B310
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/docs/source/conf.py:227`

**Description:** [B310] blacklist: Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**AI Suggested Fix:** Manual review required.

---
### 4. [MEDIUM] SAST (bandit): B102
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/docs/source/rbac/generate-scope-table.py:41`

**Description:** [B102] exec_used: Use of exec detected.

**AI Suggested Fix:** Manual review required.

---
### 5. [MEDIUM] SAST (bandit): B102
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/docs/source/rbac/generate-scope-table.py:55`

**Description:** [B102] exec_used: Use of exec detected.

**AI Suggested Fix:** Manual review required.

---
### 6. [MEDIUM] SAST (bandit): B102
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/docs/test_docs.py:20`

**Description:** [B102] exec_used: Use of exec detected.

**AI Suggested Fix:** Manual review required.

---
### 7. [MEDIUM] SAST (bandit): B104
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/examples/bootstrap-script/jupyterhub_config.py:41`

**Description:** [B104] hardcoded_bind_all_interfaces: Possible binding to all interfaces.

**AI Suggested Fix:** Manual review required.

---
### 8. [MEDIUM] SAST (bandit): B608
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/alembic/versions/99a28a4418e1_user_created.py:32`

**Description:** [B608] hardcoded_sql_expressions: Possible SQL injection vector through string-based query construction.

**AI Suggested Fix:** Manual review required.

---
### 9. [MEDIUM] SAST (bandit): B608
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/alembic/versions/99a28a4418e1_user_created.py:44`

**Description:** [B608] hardcoded_sql_expressions: Possible SQL injection vector through string-based query construction.

**AI Suggested Fix:** Manual review required.

---
### 10. [HIGH] SAST (bandit): B701
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/app.py:3210`

**Description:** [B701] jinja2_autoescape_false: By default, jinja2 sets autoescape to False. Consider using autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.

**AI Suggested Fix:** Manual review required.

---
### 11. [HIGH] SAST (bandit): B701
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/app.py:3218`

**Description:** [B701] jinja2_autoescape_false: By default, jinja2 sets autoescape to False. Consider using autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.

**AI Suggested Fix:** Manual review required.

---
### 12. [MEDIUM] SAST (bandit): B104
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/objects.py:53`

**Description:** [B104] hardcoded_bind_all_interfaces: Possible binding to all interfaces.

**AI Suggested Fix:** Manual review required.

---
### 13. [MEDIUM] SAST (bandit): B104
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/objects.py:93`

**Description:** [B104] hardcoded_bind_all_interfaces: Possible binding to all interfaces.

**AI Suggested Fix:** Manual review required.

---
### 14. [HIGH] SAST (bandit): B602
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/proxy.py:757`

**Description:** [B602] subprocess_popen_with_shell_equals_true: subprocess call with shell=True identified, security issue.

**AI Suggested Fix:** Manual review required.

---
### 15. [MEDIUM] SAST (bandit): B104
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/services/service.py:443`

**Description:** [B104] hardcoded_bind_all_interfaces: Possible binding to all interfaces.

**AI Suggested Fix:** Manual review required.

---
### 16. [MEDIUM] SAST (bandit): B108
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/spawner.py:2190`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 17. [MEDIUM] SAST (bandit): B113
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/tests/mockservice.py:56`

**Description:** [B113] request_without_timeout: Call to requests without timeout

**AI Suggested Fix:** Manual review required.

---
### 18. [MEDIUM] SAST (bandit): B103
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/tests/test_app.py:188`

**Description:** [B103] set_bad_file_permissions: Chmod setting a permissive mask 0o664 on file (secret_path).

**AI Suggested Fix:** Manual review required.

---
### 19. [MEDIUM] SAST (bandit): B103
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/tests/test_app.py:193`

**Description:** [B103] set_bad_file_permissions: Chmod setting a permissive mask 0o660 on file (secret_path).

**AI Suggested Fix:** Manual review required.

---
### 20. [MEDIUM] SAST (bandit): B103
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/tests/test_app.py:202`

**Description:** [B103] set_bad_file_permissions: Chmod setting a permissive mask 0o660 on file (secret_path).

**AI Suggested Fix:** Manual review required.

---
### 21. [MEDIUM] SAST (bandit): B104
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/tests/test_app.py:367`

**Description:** [B104] hardcoded_bind_all_interfaces: Possible binding to all interfaces.

**AI Suggested Fix:** Manual review required.

---
### 22. [MEDIUM] SAST (bandit): B108
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/tests/test_spawner.py:610`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 23. [MEDIUM] SAST (bandit): B108
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/tests/test_spawner.py:625`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 24. [MEDIUM] SAST (bandit): B104
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/utils.py:107`

**Description:** [B104] hardcoded_bind_all_interfaces: Possible binding to all interfaces.

**AI Suggested Fix:** Manual review required.

---
### 25. [MEDIUM] SAST (bandit): B104
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/utils.py:269`

**Description:** [B104] hardcoded_bind_all_interfaces: Possible binding to all interfaces.

**AI Suggested Fix:** Manual review required.

---
### 26. [HIGH] SAST (bandit): B602
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/setup.py:105`

**Description:** [B602] subprocess_popen_with_shell_equals_true: subprocess call with shell=True identified, security issue.

**AI Suggested Fix:** Manual review required.

---
### 27. [HIGH] SAST (bandit): B602
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/setup.py:158`

**Description:** [B602] subprocess_popen_with_shell_equals_true: subprocess call with shell=True identified, security issue.

**AI Suggested Fix:** Manual review required.

---
### 28. [HIGH] SAST (bandit): B602
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/setup.py:196`

**Description:** [B602] subprocess_popen_with_shell_equals_true: subprocess call with shell=True identified, security issue.

**AI Suggested Fix:** Manual review required.

---
### 29. [HIGH] SAST (bandit): B602
**Location:** `/sessions/dreamy-kind-clarke/mnt/jupyter-security-sprint-prep/repos/jupyterhub/setup.py:203`

**Description:** [B602] subprocess_popen_with_shell_equals_true: subprocess call with shell=True identified, security issue.

**AI Suggested Fix:** Manual review required.

---
### 30. [MEDIUM] SAST (semgrep): dynamic-urllib-use-detected
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/docs/source/conf.py:201`

**Description:** Detected a dynamic value being used with urllib. urllib supports 'file://' schemes, so a dynamic value controlled by a malicious actor may allow them to read arbitrary files. Audit uses of urllib calls to ensure user data cannot control the URLs, or consider using the 'requests' library instead.

**AI Suggested Fix:** Manual review required.

---
### 31. [MEDIUM] SAST (semgrep): dynamic-urllib-use-detected
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/docs/source/conf.py:210`

**Description:** Detected a dynamic value being used with urllib. urllib supports 'file://' schemes, so a dynamic value controlled by a malicious actor may allow them to read arbitrary files. Audit uses of urllib calls to ensure user data cannot control the URLs, or consider using the 'requests' library instead.

**AI Suggested Fix:** Manual review required.

---
### 32. [MEDIUM] SAST (semgrep): dynamic-urllib-use-detected
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/docs/source/conf.py:227`

**Description:** Detected a dynamic value being used with urllib. urllib supports 'file://' schemes, so a dynamic value controlled by a malicious actor may allow them to read arbitrary files. Audit uses of urllib calls to ensure user data cannot control the URLs, or consider using the 'requests' library instead.

**AI Suggested Fix:** Manual review required.

---
### 33. [MEDIUM] SAST (semgrep): request-host-used
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/docs/source/howto/configuration/config-proxy.md:57`

**Description:** '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**AI Suggested Fix:** Manual review required.

---
### 34. [MEDIUM] SAST (semgrep): request-host-used
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/docs/source/howto/configuration/config-proxy.md:84`

**Description:** '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**AI Suggested Fix:** Manual review required.

---
### 35. [MEDIUM] SAST (semgrep): request-host-used
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/docs/source/howto/configuration/config-proxy.md:103`

**Description:** '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**AI Suggested Fix:** Manual review required.

---
### 36. [MEDIUM] SAST (semgrep): request-host-used
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/docs/source/howto/configuration/config-proxy.md:103`

**Description:** '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**AI Suggested Fix:** Manual review required.

---
### 37. [MEDIUM] SAST (semgrep): request-host-used
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/docs/source/howto/configuration/config-proxy.md:118`

**Description:** '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**AI Suggested Fix:** Manual review required.

---
### 38. [MEDIUM] SAST (semgrep): exec-detected
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/docs/source/rbac/generate-scope-table.py:41`

**Description:** Detected the use of exec(). exec() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.

**AI Suggested Fix:** Manual review required.

---
### 39. [MEDIUM] SAST (semgrep): exec-detected
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/docs/source/rbac/generate-scope-table.py:55`

**Description:** Detected the use of exec(). exec() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.

**AI Suggested Fix:** Manual review required.

---
### 40. [MEDIUM] SAST (semgrep): exec-detected
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/docs/test_docs.py:20`

**Description:** Detected the use of exec(). exec() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.

**AI Suggested Fix:** Manual review required.

---
### 41. [HIGH] SAST (semgrep): missing-user
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/examples/service-fastapi/Dockerfile:13`

**Description:** By not specifying a USER, a program in the container may run as 'root'. This is a security hazard. If an attacker can control a process running as root, they may have control over the container. Ensure that the last USER in a Dockerfile is a USER other than 'root'.

**AI Suggested Fix:** Manual review required.

---
### 42. [MEDIUM] SAST (semgrep): secure-set-cookie
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/examples/service-whoami-flask/whoami-flask.py:42`

**Description:** Found a Flask cookie with insecurely configured properties.  By default the secure, httponly and samesite ar configured insecurely. cookies should be handled securely by setting `secure=True`, `httponly=True`, and `samesite='Lax'` in response.set_cookie(...). If these parameters are not properly set, your cookies are not properly protected and are at risk of being stolen by an attacker. Include the `secure=True`, `httponly=True`, `samesite='Lax'` arguments or set these to be true in the Flask configuration.

**AI Suggested Fix:** Manual review required.

---
### 43. [MEDIUM] SAST (semgrep): missing-autoescape-disabled
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/app.py:3210`

**Description:** Detected a Jinja2 environment without autoescaping. Jinja2 does not autoescape by default. This is dangerous if you are rendering to a browser because this allows for cross-site scripting (XSS) attacks. If you are in a web context, enable autoescaping by setting 'autoescape=True.' You may also consider using 'jinja2.select_autoescape()' to only enable automatic escaping for certain file extensions.

**AI Suggested Fix:** Manual review required.

---
### 44. [MEDIUM] SAST (semgrep): missing-autoescape-disabled
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/app.py:3218`

**Description:** Detected a Jinja2 environment without autoescaping. Jinja2 does not autoescape by default. This is dangerous if you are rendering to a browser because this allows for cross-site scripting (XSS) attacks. If you are in a web context, enable autoescaping by setting 'autoescape=True.' You may also consider using 'jinja2.select_autoescape()' to only enable automatic escaping for certain file extensions.

**AI Suggested Fix:** Manual review required.

---
### 45. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/singleuser/templates/page.html:14`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
### 46. [LOW] SAST (semgrep): avoid-bind-to-all-interfaces
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/jupyterhub/utils.py:76`

**Description:** Running `socket.bind` to 0.0.0.0, or empty string could unexpectedly expose the server publicly as it binds to all available interfaces. Consider instead getting correct address from an environment variable or configuration file.

**AI Suggested Fix:** Manual review required.

---
### 47. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/accept-share.html:11`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 48. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/accept-share.html:11`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
### 49. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/accept-share.html:44`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
### 50. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/accept-share.html:44`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 51. [MEDIUM] SAST (semgrep): var-in-script-tag
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/admin.html:5`

**Description:** Detected a template variable used in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent cross-site scripting (XSS) attacks when used directly in JavaScript. If you need this data on the rendered page, consider placing it in the HTML portion (outside of a script tag). Alternatively, use a JavaScript-specific encoder, such as the one available in OWASP ESAPI. For Django, you may also consider using the 'json_script' template tag and retrieving the data in your script by using the element ID (e.g., `document.getElementById`).

**AI Suggested Fix:** Manual review required.

---
### 52. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/admin.html:5`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 53. [MEDIUM] SAST (semgrep): var-in-script-tag
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/admin.html:6`

**Description:** Detected a template variable used in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent cross-site scripting (XSS) attacks when used directly in JavaScript. If you need this data on the rendered page, consider placing it in the HTML portion (outside of a script tag). Alternatively, use a JavaScript-specific encoder, such as the one available in OWASP ESAPI. For Django, you may also consider using the 'json_script' template tag and retrieving the data in your script by using the element ID (e.g., `document.getElementById`).

**AI Suggested Fix:** Manual review required.

---
### 54. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/admin.html:6`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 55. [MEDIUM] SAST (semgrep): unquoted-attribute-var
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/admin.html:8`

**Description:** Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ expr }}".

**AI Suggested Fix:** Manual review required.

---
### 56. [MEDIUM] SAST (semgrep): var-in-script-tag
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/admin.html:8`

**Description:** Detected a template variable used in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent cross-site scripting (XSS) attacks when used directly in JavaScript. If you need this data on the rendered page, consider placing it in the HTML portion (outside of a script tag). Alternatively, use a JavaScript-specific encoder, such as the one available in OWASP ESAPI. For Django, you may also consider using the 'json_script' template tag and retrieving the data in your script by using the element ID (e.g., `document.getElementById`).

**AI Suggested Fix:** Manual review required.

---
### 57. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/error.html:11`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 58. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/error.html:15`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 59. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/home.html:14`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
### 60. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/home.html:59`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
### 61. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/home.html:77`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
### 62. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/login.html:12`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 63. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/login.html:21`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
### 64. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/login.html:21`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 65. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/login.html:24`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 66. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/login.html:119`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
### 67. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/not_running.html:21`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 68. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/not_running.html:43`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
### 69. [MEDIUM] SAST (semgrep): unquoted-attribute-var
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/page.html:50`

**Description:** Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ expr }}".

**AI Suggested Fix:** Manual review required.

---
### 70. [MEDIUM] SAST (semgrep): unquoted-attribute-var
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/page.html:53`

**Description:** Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ expr }}".

**AI Suggested Fix:** Manual review required.

---
### 71. [MEDIUM] SAST (semgrep): unquoted-attribute-var
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/page.html:56`

**Description:** Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ expr }}".

**AI Suggested Fix:** Manual review required.

---
### 72. [MEDIUM] SAST (semgrep): unquoted-attribute-var
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/page.html:59`

**Description:** Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ expr }}".

**AI Suggested Fix:** Manual review required.

---
### 73. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/page.html:85`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 74. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/page.html:120`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
### 75. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/page.html:165`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
### 76. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/page.html:195`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
### 77. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/page.html:200`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
### 78. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/page.html:215`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 79. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/spawn.html:20`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 80. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/spawn.html:24`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 81. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/spawn.html:27`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 82. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `/Users/akhil.au/jupyter-security-sprint-prep/repos/jupyterhub/share/jupyterhub/templates/token.html:16`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
