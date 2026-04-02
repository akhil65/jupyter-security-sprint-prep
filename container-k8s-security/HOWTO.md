# How to Run the Scans — Step by Step

Three tools. One command each. This is the complete guide to reproduce the security analysis of a real JupyterHub Kubernetes deployment.

---

## What You're Scanning

| Tool | Target | What It Finds |
|------|--------|--------------|
| **Checkov** | z2jh Helm chart (rendered to YAML) + Dockerfiles | K8s misconfigs, Dockerfile issues |
| **Grype** | Official quay.io JupyterHub and Jupyter images | Known CVEs in OS + Python packages |
| **Kubescape** | z2jh Helm chart (static) or live cluster | K8s posture vs NSA / MITRE ATT&CK |

**Why z2jh?** The `jupyterhub/jupyterhub` and `jupyterlab/jupyterlab` repos are Python application code — they don't contain K8s deployment configs. The real K8s deployment lives at `zero-to-jupyterhub-k8s` (the official Helm chart). That's what actual JupyterHub clusters run.

---

## Step 1 — Install the tools

```bash
# Checkov (Python-based IaC scanner)
pip install checkov

# Grype (container image CVE scanner) — macOS
brew install grype
# Linux
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Kubescape (K8s posture scanner) — macOS
brew install kubescape
# Linux
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash

# Helm (needed to render z2jh chart to YAML) — macOS
brew install helm
# Linux: https://helm.sh/docs/intro/install/

# Verify all installed
checkov --version && grype version && kubescape version && helm version
```

---

## Step 2 — Clone the source repos

```bash
# Make a working directory
mkdir jupyter-k8s-security && cd jupyter-k8s-security

# JupyterHub Python source (contains example Dockerfiles)
git clone --depth=1 https://github.com/jupyterhub/jupyterhub repos/jupyterhub

# JupyterLab Python source (contains some Dockerfiles)
git clone --depth=1 https://github.com/jupyterlab/jupyterlab repos/jupyterlab
```

---

## Step 3 — Render the z2jh Helm chart to static YAML

This is the key step. It downloads the official JupyterHub Helm chart and renders all K8s resources (Deployments, Services, RBAC, NetworkPolicy, etc.) to a single YAML file.

```bash
# Add the official JupyterHub Helm repo
helm repo add jupyterhub https://hub.jupyter.org/helm-chart/
helm repo update

# Render the chart — no cluster needed
helm template jupyterhub jupyterhub/jupyterhub \
  --namespace jupyter \
  --version 3.3.7 \
  > /tmp/z2jh-rendered.yaml

# Confirm it worked — should be ~2000+ lines
wc -l /tmp/z2jh-rendered.yaml

# Optional: browse what's in it
grep "^kind:" /tmp/z2jh-rendered.yaml | sort | uniq -c
```

---

## Step 4 — Run Checkov

```bash
# Scan the rendered z2jh Helm chart for K8s misconfigurations
checkov -f /tmp/z2jh-rendered.yaml --framework kubernetes

# Scan JupyterHub Dockerfiles
checkov -d repos/jupyterhub --framework dockerfile

# Scan JupyterLab Dockerfiles
checkov -d repos/jupyterlab --framework dockerfile

# Save all output to files
checkov -f /tmp/z2jh-rendered.yaml --framework kubernetes -o json > checkov-z2jh.json
checkov -d repos/jupyterhub --framework dockerfile -o json > checkov-dockerfiles.json
```

**What to look for:**
- `FAILED` lines are the findings
- The CKV_K8S_* codes map to specific K8s security controls
- `--compact` flag reduces noise; `--check CKV_K8S_6,CKV_K8S_20` scans specific checks only

---

## Step 5 — Run Grype

```bash
# Update the CVE database first (important — stale DB = missed CVEs)
grype db update

# Scan the official JupyterHub image
grype quay.io/jupyterhub/jupyterhub:5.3.0

# Scan the official Jupyter scipy-notebook image (used as single-user server)
grype quay.io/jupyter/scipy-notebook:2024-10-07

# Scan the postgres:9.3 image used in JupyterHub examples (expected: many CVEs, all unfixable)
grype postgres:9.3

# Show only Critical and High
grype quay.io/jupyterhub/jupyterhub:5.3.0 | grep -E "Critical|High"

# Save JSON for programmatic processing
grype quay.io/jupyterhub/jupyterhub:5.3.0 -o json > grype-jupyterhub.json

# Count CVEs by severity
python3 -c "
import json, collections
d = json.load(open('grype-jupyterhub.json'))
c = collections.Counter(m['vulnerability']['severity'] for m in d['matches'])
for sev, count in sorted(c.items()): print(f'  {sev}: {count}')
"
```

**What to look for:**
- `Critical` / `High` rows with a `Fixed In` version → upgrade immediately
- `Critical` / `High` rows with no `Fixed In` → the base OS or package is EOL, needs image upgrade
- postgres:9.3 will show all unfixed — that's expected, it's a 10-year-old EOL image

---

## Step 6 — Run Kubescape

```bash
# Scan the rendered z2jh Helm chart — NSA Hardening Framework
kubescape scan framework nsa /tmp/z2jh-rendered.yaml

# MITRE ATT&CK for Containers
kubescape scan framework mitre /tmp/z2jh-rendered.yaml

# CIS Kubernetes Benchmark
kubescape scan framework cis-k8s /tmp/z2jh-rendered.yaml

# Specific high-value controls
kubescape scan control C-0016,C-0012,C-0004,C-0046,C-0021,C-0260 \
  /tmp/z2jh-rendered.yaml

# Save JSON
kubescape scan framework nsa /tmp/z2jh-rendered.yaml \
  --format json > kubescape-nsa.json
```

**What to look for:**
- The "Risk score" percentage at the top — lower is better
- `FAILED` controls with severity HIGH or CRITICAL
- C-0016 (privilege escalation), C-0012 (hardcoded creds), C-0260 (NetworkPolicy) are the most important

---

## Step 7 (Optional) — Live cluster scan with kind

Only do this if you want to scan an actual running cluster instead of static YAML.

```bash
# Install kind
brew install kind   # macOS
# Linux: https://kind.sigs.k8s.io/docs/user/quick-start/#installation

# Create a local cluster
kind create cluster --name jupyter-security

# Install JupyterHub via Helm
kubectl create namespace jupyter
helm install jupyterhub jupyterhub/jupyterhub \
  --namespace jupyter \
  --version 3.3.7 \
  --timeout 10m

# Wait for hub to start
kubectl -n jupyter rollout status deployment/hub

# Now scan the live cluster (kubescape reads from your kubeconfig automatically)
kubescape scan framework nsa --namespace jupyter
kubescape scan framework mitre --namespace jupyter

# Clean up when done
kind delete cluster --name jupyter-security
```

---

## Interpreting the Results

**Checkov output format:**
```
Check: CKV_K8S_20: "Containers should not run with allowPrivilegeEscalation"
  FAILED for resource: jupyter/Deployment.hub
  File: /tmp/z2jh-rendered.yaml:45-112
  Guide: https://docs.bridgecrew.io/docs/bc_k8s_20
```
Each failure gives you the exact resource, line number, and a link to the fix.

**Grype output format:**
```
NAME        INSTALLED   FIXED-IN  TYPE    VULNERABILITY   SEVERITY
aiohttp     3.9.3       3.9.4     python  CVE-2024-23334  Critical
tornado     6.4         6.4.1     python  CVE-2024-49769  High
```
`Fixed-In` blank = no patch available for this OS/image version.

**Kubescape output format:**
```
Control: Minimize the admission of containers wishing to share the host network namespace (C-0041)
  Status: FAILED
  Affected resources: [jupyter/Deployment/hub]
  ...
Risk score: 68%   Failed: 10/21 controls
```

---

## Running the Module's Pre-Built Scripts

If you've cloned this repo, the run scripts automate all the steps above. Here is the complete walkthrough with expected terminal output.

### Script 1 — Checkov (`scans/checkov/run-checkov.sh`)

```bash
cd container-k8s-security
bash scans/checkov/run-checkov.sh
```

**What it does:** Adds the JupyterHub Helm repo, renders the z2jh chart to `/tmp/z2jh-rendered.yaml`, then runs Checkov against it. Also scans Dockerfiles in `repos/jupyterhub/` if cloned.

**Expected terminal output:**

```
═══════════════════════════════════════════════════════════
  Checkov IaC Scan — Jupyter K8s Security
═══════════════════════════════════════════════════════════

[1/3] Rendering z2jh Helm chart (official JupyterHub K8s deployment)...
  Rendered 2184 lines of K8s YAML

Check: CKV_K8S_21: "The default namespace should not be used"
  FAILED for resource: default/Deployment.continuous-image-puller
  ...

Passed checks: 553, Failed checks: 113, Skipped checks: 0

[2/3] Scanning repos/jupyterhub/ Dockerfiles...
  -> scans/checkov/jupyterhub_dockerfile.txt

═══════════════════════════════════════════════════════════
  Done. Key output:
    z2jh K8s scan : scans/checkov/z2jh_k8s_scan.txt
    Dockerfiles   : scans/checkov/jupyterhub_dockerfile.txt
═══════════════════════════════════════════════════════════
```

**Output files saved:**

| File | Contents |
|------|----------|
| `scans/checkov/z2jh_k8s_scan.txt` | Human-readable list of all 113 failed checks |
| `scans/checkov/z2jh_k8s_scan.json` | Full JSON with resource names, line numbers, guideline links |
| `scans/checkov/jupyterhub_dockerfile.txt` | Dockerfile findings |

**How to read the results:**

```
# Show only failed checks
grep "FAILED" scans/checkov/z2jh_k8s_scan.txt

# Count failures by check ID
grep "Check:" scans/checkov/z2jh_k8s_scan.txt | sort | uniq -c | sort -rn

# See the full detail for one check
grep -A 5 "CKV_K8S_35" scans/checkov/z2jh_k8s_scan.txt
```

---

### Script 2 — Grype (`scans/grype/run-grype.sh`)

```bash
bash scans/grype/run-grype.sh
```

**What it does:** Updates the Grype CVE database, then pulls and scans three images: `jupyterhub:5.3.0`, `scipy-notebook:2024-10-07`, and `postgres:9.3`.

**Expected terminal output:**

```
═══════════════════════════════════════════════════════════
  Grype Container Image CVE Scan — Jupyter Security Sprint
═══════════════════════════════════════════════════════════

Updating grype vulnerability database...
 ✔ Vulnerability DB  [updated]

[1/3] Scanning JupyterHub image: quay.io/jupyterhub/jupyterhub:5.3.0
 ✔ Loaded image
 ✔ Parsed image
 ✔ Cataloged packages      [312 packages]
 ✔ Scanned for vulnerabilities [482 vulnerabilities]

NAME                  INSTALLED   FIXED-IN  TYPE    VULNERABILITY   SEVERITY
tornado               6.5.2       6.5.5     python  GHSA-qjxf-...   High
urllib3               2.5.0       2.6.0     python  GHSA-gm62-...   High
cryptography          46.0.2      46.0.5    python  GHSA-r6ph-...   High
...

[2/3] Scanning JupyterLab image: quay.io/jupyter/scipy-notebook:2024-10-07
 ✔ Cataloged packages      [847 packages]
 ✔ Scanned for vulnerabilities [1540 vulnerabilities]

NAME      INSTALLED  FIXED-IN  TYPE    VULNERABILITY        SEVERITY
h11       0.14.0     0.16.0    python  GHSA-vqfr-h8mv-ghfj  Critical
python    3.11.10    3.9.23    python  CVE-2025-4517        Critical
nbconvert 7.16.4     7.17.0    python  GHSA-xm59-rqc7-hhvf  High
...

[3/3] Scanning deprecated postgres:9.3
 ✔ Cataloged packages      [194 packages]
 ✔ Scanned for vulnerabilities [948 vulnerabilities]
   (157 Critical — EOL base OS, no fixes available)
```

**Output files saved:**

| File | Contents |
|------|----------|
| `scans/grype/jupyterhub_image_real.json` | Full JSON CVE report for jupyterhub:5.3.0 |
| `scans/grype/jupyterhub_image_summary.txt` | Critical/High rows only — table format |
| `scans/grype/jupyterlab_image_summary.txt` | Critical/High for scipy-notebook |
| `scans/grype/postgres93_summary.txt` | Critical/High for postgres:9.3 |

**How to read the results:**

```bash
# Count CVEs by severity for any image
python3 -c "
import json, collections
d = json.load(open('scans/grype/jupyterhub_image_real.json'))
c = collections.Counter(m['vulnerability']['severity'] for m in d['matches'])
for sev, n in sorted(c.items()): print(f'  {sev}: {n}')
"

# Show only fixable Critical/High
grype quay.io/jupyterhub/jupyterhub:5.3.0 --only-fixed | grep -E "Critical|High"

# Export SBOM alongside CVE report
grype quay.io/jupyterhub/jupyterhub:5.3.0 -o json > jupyterhub.json
syft quay.io/jupyterhub/jupyterhub:5.3.0 -o spdx-json > jupyterhub-sbom.json
```

---

### Script 3 — Kubescape (`scans/kubescape/run-kubescape.sh`)

```bash
# Static scan (uses /tmp/z2jh-rendered.yaml — run Checkov script first)
bash scans/kubescape/run-kubescape.sh

# Live cluster scan (requires a running cluster via kubeconfig)
bash scans/kubescape/run-kubescape.sh --live-cluster
```

**What it does:** Scans the rendered z2jh Helm YAML against NSA Hardening and MITRE ATT&CK frameworks. With `--live-cluster`, reads your active kubeconfig and scans the running cluster.

**Expected terminal output:**

```
═══════════════════════════════════════════════════════════
  Kubescape K8s Security Scan — Jupyter K8s Security
═══════════════════════════════════════════════════════════
  Target: z2jh rendered Helm chart (/tmp/z2jh-rendered.yaml)

[1/3] NSA Kubernetes Hardening Framework...

┌──────────────────────────────────────────────────────────┐
│ NSA Kubernetes Hardening Framework Scan Results          │
├──────────────────────────────────────────────────────────┤
│ Compliance score: 76.9%                                  │
│ Controls failed: 6 / 20                                  │
└──────────────────────────────────────────────────────────┘

Control: Applications credentials in configuration files (C-0012)  [High]
  Status: FAILED
  Affected: hub Deployment — env var PROXY_SECRET_TOKEN

Control: Ensure CPU limits are set (C-0270)  [High]
  Status: FAILED
  Affected: 7 containers across hub, proxy, user pods
...

[2/3] MITRE ATT&CK for Containers...

Compliance score: 87.6%   Controls failed: 4 / 17

  C-0012 [High]    Applications credentials in configuration files
  C-0015 [High]    List Kubernetes secrets
  C-0007 [Medium]  Roles with delete capabilities
  C-0053 [Medium]  Access container service account
```

**Output files saved:**

| File | Contents |
|------|----------|
| `scans/kubescape/nsa_results.txt` | NSA framework — full human-readable report |
| `scans/kubescape/nsa_results.json` | NSA framework — full JSON (controls, resources, scores) |
| `scans/kubescape/mitre_results.txt` | MITRE ATT&CK — full report |
| `scans/kubescape/mitre_results.json` | MITRE ATT&CK — full JSON |
| `scans/kubescape/nsa_results_real.json` | Real scan result from actual run |

**How to read the results:**

```bash
# Quick risk score summary
kubescape scan framework nsa /tmp/z2jh-rendered.yaml 2>&1 | grep -E "score|Failed|Passed"

# Scan a single specific control
kubescape scan control C-0012 /tmp/z2jh-rendered.yaml

# Compare before/after hardening
kubescape scan framework nsa /tmp/z2jh-defaults.yaml   # baseline
kubescape scan framework nsa /tmp/z2jh-hardened.yaml   # after values override
```

---

### Saving All Results in One Go

```bash
mkdir -p ~/jupyter-security-results
cd container-k8s-security

bash scans/checkov/run-checkov.sh   2>&1 | tee ~/jupyter-security-results/checkov-run.log
bash scans/grype/run-grype.sh       2>&1 | tee ~/jupyter-security-results/grype-run.log
bash scans/kubescape/run-kubescape.sh 2>&1 | tee ~/jupyter-security-results/kubescape-run.log

# Copy all JSON/txt outputs
cp scans/checkov/*.{json,txt} ~/jupyter-security-results/ 2>/dev/null
cp scans/grype/*.{json,txt}   ~/jupyter-security-results/ 2>/dev/null
cp scans/kubescape/*.{json,txt} ~/jupyter-security-results/ 2>/dev/null

echo "All results saved to ~/jupyter-security-results/"
ls -lh ~/jupyter-security-results/
```
