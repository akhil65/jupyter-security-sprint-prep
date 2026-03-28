# Security Findings Dashboard: jupyter_server

## Overview
This report aggregates findings across SAST, SCA, Secrets, IaC, DAST, and AI-SPM for the target repository.

### Risk Breakdown
- **SAST:** 34
- **SCA:** 0
- **SECRETS:** 0
- **IAC:** 0
- **DAST:** 0
- **AI-SPM:** 0

## Actionable True Positives (34)

### 1. [MEDIUM] SAST (bandit): B604
**Location:** `jupyter_server/jupyter_server/gateway/managers.py:765`

**Description:** [B604] any_other_function_with_shell_equals_true: Function call with shell=True parameter identified, possible security issue.

**AI Suggested Fix:** Manual review required.

---
### 2. [HIGH] SAST (bandit): B701
**Location:** `jupyter_server/jupyter_server/serverapp.py:383`

**Description:** [B701] jinja2_autoescape_false: By default, jinja2 sets autoescape to False. Consider using autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.

**AI Suggested Fix:** Manual review required.

---
### 3. [MEDIUM] SAST (bandit): B104
**Location:** `jupyter_server/jupyter_server/serverapp.py:2359`

**Description:** [B104] hardcoded_bind_all_interfaces: Possible binding to all interfaces.

**AI Suggested Fix:** Manual review required.

---
### 4. [MEDIUM] SAST (bandit): B608
**Location:** `jupyter_server/jupyter_server/services/sessions/sessionmanager.py:411`

**Description:** [B608] hardcoded_sql_expressions: Possible SQL injection vector through string-based query construction.

**AI Suggested Fix:** Manual review required.

---
### 5. [MEDIUM] SAST (bandit): B608
**Location:** `jupyter_server/jupyter_server/services/sessions/sessionmanager.py:459`

**Description:** [B608] hardcoded_sql_expressions: Possible SQL injection vector through string-based query construction.

**AI Suggested Fix:** Manual review required.

---
### 6. [MEDIUM] SAST (bandit): B113
**Location:** `jupyter_server/tests/extension/test_launch.py:36`

**Description:** [B113] request_without_timeout: Call to requests without timeout

**AI Suggested Fix:** Manual review required.

---
### 7. [MEDIUM] SAST (bandit): B113
**Location:** `jupyter_server/tests/extension/test_launch.py:94`

**Description:** [B113] request_without_timeout: Call to requests without timeout

**AI Suggested Fix:** Manual review required.

---
### 8. [MEDIUM] SAST (bandit): B103
**Location:** `jupyter_server/tests/services/contents/test_fileio.py:34`

**Description:** [B103] set_bad_file_permissions: Chmod setting a permissive mask 0o701 on file (NOT PARSED).

**AI Suggested Fix:** Manual review required.

---
### 9. [MEDIUM] SAST (bandit): B108
**Location:** `jupyter_server/tests/services/contents/test_fileio.py:175`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 10. [MEDIUM] SAST (bandit): B108
**Location:** `jupyter_server/tests/services/contents/test_fileio.py:176`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 11. [MEDIUM] SAST (bandit): B108
**Location:** `jupyter_server/tests/services/contents/test_fileio.py:172`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 12. [MEDIUM] SAST (bandit): B108
**Location:** `jupyter_server/tests/test_serverapp.py:208`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 13. [MEDIUM] SAST (bandit): B108
**Location:** `jupyter_server/tests/test_serverapp.py:219`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 14. [MEDIUM] SAST (bandit): B108
**Location:** `jupyter_server/tests/test_serverapp.py:220`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 15. [MEDIUM] SAST (bandit): B108
**Location:** `jupyter_server/tests/test_serverapp.py:221`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 16. [MEDIUM] SAST (bandit): B108
**Location:** `jupyter_server/tests/test_serverapp.py:221`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 17. [MEDIUM] SAST (bandit): B108
**Location:** `jupyter_server/tests/test_serverapp.py:307`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 18. [MEDIUM] SAST (bandit): B108
**Location:** `jupyter_server/tests/test_serverapp.py:313`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 19. [MEDIUM] SAST (bandit): B108
**Location:** `jupyter_server/tests/test_terminal.py:199`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 20. [MEDIUM] SAST (bandit): B108
**Location:** `jupyter_server/tests/test_utils.py:120`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 21. [MEDIUM] SAST (bandit): B108
**Location:** `jupyter_server/tests/unix_sockets/conftest.py:20`

**Description:** [B108] hardcoded_tmp_directory: Probable insecure usage of temp file/directory.

**AI Suggested Fix:** Manual review required.

---
### 22. [MEDIUM] SAST (semgrep): unquoted-attribute-var
**Location:** `jupyter_server/examples/simple/simple_ext1/templates/page.html:6`

**Description:** Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ expr }}".

**AI Suggested Fix:** Manual review required.

---
### 23. [MEDIUM] SAST (semgrep): unquoted-attribute-var
**Location:** `jupyter_server/examples/simple/simple_ext2/templates/page.html:6`

**Description:** Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ expr }}".

**AI Suggested Fix:** Manual review required.

---
### 24. [MEDIUM] SAST (semgrep): python-logger-credential-disclosure
**Location:** `jupyter_server/jupyter_server/auth/__main__.py:41`

**Description:** Detected a python logger call with a potential hardcoded secret "password stored in config dir: %s" % jupyter_config_dir() being logged. This may lead to secret credentials being exposed. Make sure that the logger is not logging  sensitive information.

**AI Suggested Fix:** Manual review required.

---
### 25. [MEDIUM] SAST (semgrep): missing-autoescape-disabled
**Location:** `jupyter_server/jupyter_server/serverapp.py:383`

**Description:** Detected a Jinja2 environment without autoescaping. Jinja2 does not autoescape by default. This is dangerous if you are rendering to a browser because this allows for cross-site scripting (XSS) attacks. If you are in a web context, enable autoescaping by setting 'autoescape=True.' You may also consider using 'jinja2.select_autoescape()' to only enable automatic escaping for certain file extensions.

**AI Suggested Fix:** Manual review required.

---
### 26. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `jupyter_server/jupyter_server/templates/browser-open.html:14`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
### 27. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `jupyter_server/jupyter_server/templates/login.html:18`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 28. [MEDIUM] SAST (semgrep): template-unescaped-with-safe
**Location:** `jupyter_server/jupyter_server/templates/login.html:88`

**Description:** Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

**AI Suggested Fix:** Manual review required.

---
### 29. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `jupyter_server/jupyter_server/templates/logout.html:26`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
### 30. [MEDIUM] SAST (semgrep): unquoted-attribute-var
**Location:** `jupyter_server/jupyter_server/templates/page.html:9`

**Description:** Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ expr }}".

**AI Suggested Fix:** Manual review required.

---
### 31. [MEDIUM] SAST (semgrep): unquoted-attribute-var
**Location:** `jupyter_server/jupyter_server/templates/page.html:11`

**Description:** Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ expr }}".

**AI Suggested Fix:** Manual review required.

---
### 32. [MEDIUM] SAST (semgrep): unquoted-attribute-var
**Location:** `jupyter_server/jupyter_server/templates/page.html:12`

**Description:** Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ expr }}".

**AI Suggested Fix:** Manual review required.

---
### 33. [MEDIUM] SAST (semgrep): unquoted-attribute-var
**Location:** `jupyter_server/jupyter_server/templates/page.html:13`

**Description:** Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ expr }}".

**AI Suggested Fix:** Manual review required.

---
### 34. [MEDIUM] SAST (semgrep): var-in-href
**Location:** `jupyter_server/jupyter_server/templates/page.html:37`

**Description:** Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

**AI Suggested Fix:** Manual review required.

---
