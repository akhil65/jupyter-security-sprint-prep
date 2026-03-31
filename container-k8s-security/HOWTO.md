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

If you've cloned this repo, the run scripts automate steps 4–6:

```bash
cd container-k8s-security

# Checkov — renders z2jh first, then scans
bash scans/checkov/run-checkov.sh

# Grype — scans all 3 images
bash scans/grype/run-grype.sh

# Kubescape — uses /tmp/z2jh-rendered.yaml if present (run Checkov step first)
bash scans/kubescape/run-kubescape.sh

# Kubescape against a live cluster
bash scans/kubescape/run-kubescape.sh --live-cluster
```

Results land in `scans/checkov/`, `scans/grype/`, and `scans/kubescape/` respectively.
Pre-canned outputs (matching real tool format) are already there for reference.
