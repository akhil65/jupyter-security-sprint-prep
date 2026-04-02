# Jupyter Security

This repository contains the outcome of the **Jupyter Security Tooling Sprint** (an initiative focused on assessing Jupyter environment risks, integrating open-source security tooling, and hardening deployments against remote code execution and data exfiltration).

While baseline static analysis tools (like Bandit, Semgrep, and pip-audit) were explored in the `notes/` directory, this repository introduces a "Next Level" security control: **A Real-Time Jupyter Execution Firewall**.

## The Project: Jupyter Security Firewall (`jupyter_sec_firewall`)

Instead of just scanning notebooks after they are written, `jupyter_sec_firewall` is a Jupyter Server Extension that acts as an active execution firewall. It intercepts code that a user attempts to run in a notebook cell *before* it reaches the IPython kernel over ZeroMQ.

The extension parses the Python Abstract Syntax Tree (AST) of the incoming code and blocks malicious or unauthorized commands (such as unauthorized shell executions, restricted module imports, and dangerous dunder-based sandbox escapes) in real time. If a violation is detected, the execution is blocked, and an error is returned directly to the user's notebook cell mimicking a standard kernel error.

### Key Features
* **Real-Time Interception:** Hooks into the backend Jupyter Server WebSocket connection (`ZMQChannelsWebsocketConnection`) to intercept `execute_request` messages.
* **Protocol Aware:** Supports both legacy JSON WebSockets and the modern multiplexed `v1.kernel.websocket.jupyter.org` binary subprotocol.
* **AST Analyzer:** Analyzes the Python code for:
  * Restricted modules (`os`, `subprocess`, `socket`, `pty`, `importlib`, `sys`, `shutil`, `urllib`, `http`, `requests`).
  * Restricted builtins and dynamic code execution (`eval`, `exec`, `compile`, `__import__`, `getattr`, `setattr`, `delattr`). Note: `open` is intentionally **not** blocked to preserve legitimate data science file I/O.
  * Dangerous dunder attribute access (`__class__`, `__subclasses__`, `__mro__`, `__bases__`, `__builtins__`) to prevent sandbox escapes via Python's object hierarchy.
  * **IPython magic handling:** Shell escape commands (`!cmd`) and shell cell magics (`%%bash`, `%%sh`) are explicitly detected and blocked with a clear `SecurityError`. Standard line/cell magics (`%matplotlib inline`, `%%timeit`, etc.) are stripped before AST analysis so they pass through — legitimate data science notebooks are not broken.
* **Fail-Closed Design:** If a message is malformed or unparseable, it is dropped and not forwarded to the ZeroMQ kernel channels.
* **Seamless UI Integration:** When code is blocked, the extension synthesizes `execute_reply` and `error` messages back to the frontend, so the user sees a clear "Security Policy Violation" error inline in their notebook.

---

## Installation and Walkthrough

### 1. Install the Extension
The extension is packaged using `hatchling` and `pyproject.toml`. You can install it locally in editable mode:

```bash
# Clone the repository and navigate to the root directory
pip install -e .
```

### 2. Enable the Extension
Once installed, the extension should be enabled automatically via the configuration file placed in `etc/jupyter/jupyter_server_config.d/`. You can verify it is enabled by running:

```bash
jupyter server extension list
```

You should see `jupyter_sec_firewall` listed and enabled.

### 3. Test the Defense (Walkthrough)
Start your Jupyter Server:

```bash
jupyter server
# Or start JupyterLab / Jupyter Notebook
# jupyter lab
```

Then open a browser, navigate to the URL printed by the server, and try these exercises in a new Python notebook:

1. **Open a new Python notebook.**

2. **Run Safe Code:** Try executing basic Python code.
   ```python
   print("Hello, secure world!")
   x = 10 + 20
   x
   ```
   *Expected Outcome:* The code executes normally and outputs the result.

3. **Run Malicious Code:** Try executing a command that violates the security policy.
   ```python
   import os
   os.system("cat /etc/passwd")
   ```
   *Expected Outcome:* The cell execution is blocked instantly. You will see an error output in the cell:
   ```text
   SecurityError: Security Policy Violation
   Security Policy Violation Blocked Execution
   - Unauthorized import detected: os
   ```

4. **Attempt a Sandbox Escape:** Try accessing restricted dunder methods.
   ```python
   ().__class__.__bases__[0].__subclasses__()
   ```
   *Expected Outcome:* The AST analyzer flags the access to `__class__` and `__bases__`, blocking the execution.

### 4. Run the Automated Integration Test
`test_ws.py` exercises the firewall over a real WebSocket connection. Start the server with a known token first, then run the test:

```bash
jupyter server --IdentityProvider.token=testtoken --port=8888 &
sleep 3  # wait for server to start
python test_ws.py
```

This runs 6 tests: safe code passes, `import os` is blocked, `open()` is allowed, `eval()` is blocked, `!echo` shell escape is blocked, and `%matplotlib inline` line magic passes through.

### Next Steps / Future Enhancements
* **Policy Engine:** Move `RESTRICTED_MODULES` and builtins to a configurable JSON policy file so administrators can tailor the ruleset per deployment.
* **eBPF Integration (The "Next-Next" Level):** Integrate this extension with eBPF tools like Tetragon. If an obfuscated payload bypasses the AST parser and spawns an unexpected process, eBPF kills it at the Linux kernel level and reports the incident back to the Jupyter UI.

---

## The Sprint Tool: AppSec Pipeline Evaluator (`appsec_sprint_evaluator`)

`appsec_sprint_evaluator` is a CLI tool that orchestrates a full 7-stage Application Security pipeline — SAST (bandit/semgrep), SCA (pip-audit), secrets detection, IaC scanning, AI-SPM, DAST, and AI-assisted triage — then consolidates findings into a unified Markdown/JSON dashboard and optionally opens draft GitHub PRs with AI-suggested fixes.

### Quick Start

```bash
# Install (from the project root)
pip install -e appsec_sprint_evaluator/

# Run the interactive tutorial against the training_playground demo files
# IMPORTANT: always run from the project root — the tool resolves scans/, notes/,
# and output/ as relative paths from your working directory.
appsec-tutorial

# Run the full pipeline against a real repo (after running scan scripts in scans/)
appsec-eval --target-repo jupyter_server
appsec-eval --target-repo jupyterhub
```

See [`appsec_sprint_evaluator/training_playground/README.md`](appsec_sprint_evaluator/training_playground/README.md) for the full walkthrough, and [`notes/`](notes/) for scan findings and tool comparison notes.

### Re-running Scans

Each scan directory has a run script:

```bash
bash scans/bandit/run-bandit.sh       # SAST — bandit
bash scans/semgrep/run-semgrep.sh     # SAST — semgrep (requires network)
bash scans/pip-audit/run-pip-audit.sh # SCA  — pip-audit (requires network)
```

---

## Container & Kubernetes Security (`container-k8s-security/`)

A dedicated module showcasing three open-source K8s/container security tools applied to the official JupyterHub Kubernetes deployment.

| Tool | Target | Finds |
|------|--------|-------|
| **Checkov** | z2jh Helm chart + Dockerfiles | IaC misconfigurations |
| **Grype** | Official quay.io Jupyter images | Known CVEs |
| **Kubescape** | z2jh Helm chart (static + live) | K8s posture vs NSA / MITRE ATT&CK |

### Real Scan Results

Actual tool runs against the official JupyterHub Helm chart v3.3.7 and published images:

| Target | Critical | High | Key Finding |
|--------|----------|------|-------------|
| jupyterhub:5.3.0 | 0 | 22 | urllib3, tornado, cryptography — all fixable |
| scipy-notebook:2024-10-07 | 2 | 48 | h11 Critical (GHSA-vqfr-h8mv-ghfj), nbconvert XSS fixed in 7.17.0 |
| postgres:9.3 | 157 | 319 | 948 CVEs total — EOL base OS, replace with postgres:16 |
| z2jh Helm chart | — | — | 113/666 checks failed (17%); NSA 76.9%; MITRE 87.6% |

Full analysis: [`output/jupyter-security-results/real-scan-analysis.md`](output/jupyter-security-results/real-scan-analysis.md)

### Running the Scans Yourself

```bash
# Install tools
pip install checkov
brew install grype kubescape helm   # macOS

# Render the official z2jh Helm chart to YAML (the real K8s scan target)
helm repo add jupyterhub https://hub.jupyter.org/helm-chart/ && helm repo update
helm template jupyterhub jupyterhub/jupyterhub --namespace jupyter > /tmp/z2jh-rendered.yaml

# Run all three tools
checkov -f /tmp/z2jh-rendered.yaml --framework kubernetes
grype db update && grype quay.io/jupyterhub/jupyterhub:5.3.0
kubescape scan framework nsa /tmp/z2jh-rendered.yaml
```

See [`container-k8s-security/HOWTO.md`](container-k8s-security/HOWTO.md) for the complete step-by-step guide.

---

## Reports & Outputs

All dashboards and reports are in [`output/`](output/):

| File | Description |
|------|-------------|
| `output/jupyter_server_security_dashboard.md` | SAST/SCA findings — jupyter_server |
| `output/jupyterhub_security_dashboard.md` | SAST/SCA findings — jupyterhub |
| `output/training_playground_security_dashboard.md` | AppSec pipeline demo findings |
| `output/architecture-explainer.html` | Interactive visual explainer (open in browser) |
| `output/jupyter-security-results/real-scan-analysis.md` | **Real** Checkov + Grype + Kubescape findings |
| `container-k8s-security/output/container-k8s-security-dashboard.md` | K8s security dashboard |
| `notes/semgrep-findings.md` | Semgrep findings with severity breakdown |
| `notes/tool-comparison.md` | Tool comparison across all scanners |
