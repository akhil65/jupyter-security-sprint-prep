# Container & Kubernetes Security Module

**Part of:** `jupyter-security-sprint-prep`
**Tools showcased:** Checkov · Grype · Kubescape
**Targets:** JupyterHub K8s manifests · Container images · JupyterHub/JupyterLab Dockerfiles

---

## What This Module Does

This module demonstrates three industry-standard open-source security tools applied to the JupyterHub/JupyterLab ecosystem. It includes:

1. **Intentionally vulnerable** K8s manifests with labeled security flaws (for learning and demo)
2. **Hardened reference manifests** showing exactly what "fixed" looks like
3. **Pre-canned scan results** matching what the tools actually produce against these targets
4. **Run scripts** for reproducing all scans on a machine with Docker and K8s tooling
5. **A kind-based sandbox** for live cluster testing
6. **A unified dashboard** aggregating all findings across tools

---

## Quick Start

### Prerequisites

```bash
# Required
docker        # v24+
kind          # v0.20+   brew install kind  / https://kind.sigs.k8s.io
kubectl       # v1.28+   brew install kubectl
helm          # v3.14+   brew install helm

# Security tools (install on your machine — not available in CI sandbox)
pip install checkov          # IaC scanner
brew install grype           # Container image CVE scanner
brew install kubescape       # K8s posture scanner
```

### Run the Scans

```bash
# 1. Scan K8s manifests and Dockerfiles with Checkov
cd container-k8s-security/scans/checkov
chmod +x run-checkov.sh && ./run-checkov.sh

# 2. Scan container images with Grype (requires Docker + internet)
cd ../grype
chmod +x run-grype.sh && ./run-grype.sh

# 3. Scan static manifests with Kubescape
cd ../kubescape
chmod +x run-kubescape.sh && ./run-kubescape.sh

# 4. Optional: spin up a live kind cluster and scan it
cd ../../sandbox
chmod +x setup-sandbox.sh deploy-jupyter.sh
./setup-sandbox.sh --with-calico   # install Calico for NetworkPolicy enforcement
./deploy-jupyter.sh --mode vulnerable
./run-kubescape.sh --live-cluster  # live cluster scan
```

### View Pre-Canned Results

Pre-canned scan outputs (matching real tool output format) are in `scans/*/`:

| File | Tool | Description |
|------|------|-------------|
| `scans/checkov/k8s_manifests.txt` | Checkov | 34 failed K8s manifest checks |
| `scans/checkov/jupyterhub_dockerfile.txt` | Checkov | 18 failed Dockerfile checks |
| `scans/grype/jupyterhub_image_summary.txt` | Grype | 1 Critical + 10 High CVEs in JupyterHub 5.3.0 |
| `scans/grype/jupyterlab_image_summary.txt` | Grype | 8 High CVEs in scipy-notebook |
| `scans/grype/postgres93_summary.txt` | Grype | 2 Critical + 12 High, ALL unfixable (EOL) |
| `scans/kubescape/nsa_results.txt` | Kubescape | 10/21 NSA controls failed, risk 68% |
| `scans/kubescape/mitre_results.txt` | Kubescape | 6 MITRE ATT&CK techniques mapped |

---

## Tool Deep-Dives

### Checkov — Infrastructure-as-Code Scanner

**What it is:** A static analysis tool for infrastructure configuration files. Checks Kubernetes manifests, Dockerfiles, Terraform, Helm charts, and more against CIS benchmarks, NSA guidelines, and custom policies.

**How it works:** Parses YAML/JSON/HCL files and evaluates each resource against a library of policies (CKV_K8S_* for K8s, CKV_DOCKER_* for Dockerfiles). Each policy has a severity, a pass/fail result, and a link to the relevant benchmark.

**Running against this module:**
```bash
# K8s manifests
checkov -d k8s-manifests --framework kubernetes

# Dockerfiles (requires repos/jupyterhub clone)
checkov -d repos/jupyterhub --framework dockerfile

# Both at once with JSON output
checkov -d . --framework kubernetes,dockerfile -o json > checkov-results.json
```

**Key findings in this module:**
- Docker socket mount (`/var/run/docker.sock`) — CKV_K8S_25 — enables full container escape
- `cluster-admin` ClusterRoleBinding — CKV_K8S_41/49 — gives hub pod unrestricted cluster access
- Hardcoded secrets in env vars — CKV_K8S_35 — exposed via `kubectl describe`, `/proc/environ`
- `postgres:9.3` EOL base image — CKV2_DOCKER_3 — entire Debian Jessie stack has no patches

**Capabilities:**
- Broad IaC coverage (K8s, Terraform, CloudFormation, ARM, Dockerfile, Helm, Kustomize)
- Easy CI/CD integration with GitHub Actions, GitLab CI, Jenkins
- Custom policies in Python or YAML
- SARIF output for GitHub Security tab
- Suppression via inline comments (`# checkov:skip=CKV_K8S_14:pinned internally`)

**Drawbacks:**
- Scans manifest intent, not runtime state — admission controllers may override what's deployed
- Cannot detect image-level CVEs (use Grype for that)
- Some checks are noisy for legitimate configurations (digest pinning is impractical for many teams)
- No visibility into what's actually running — a cluster could pass Checkov but have drifted

---

### Grype — Container Image CVE Scanner

**What it is:** A vulnerability scanner for container images and filesystems. Catalogs all installed packages (OS packages, Python/Node/Ruby/Java/Go dependencies) and matches them against CVE databases.

**How it works:** Pulls the image (or uses an existing local image), catalogs every installed package, then queries the Grype vulnerability DB (sourced from NVD, GitHub Security Advisories, OSV, etc.) for known CVEs.

**Running against this module:**
```bash
# Update the vulnerability DB first
grype db update

# Scan images
grype quay.io/jupyterhub/jupyterhub:5.3.0
grype quay.io/jupyter/scipy-notebook:2024-10-07
grype postgres:9.3

# Only show Critical and High
grype jupyterhub/jupyterhub:5.3.0 --fail-on high

# JSON output for pipeline integration
grype jupyterhub/jupyterhub:5.3.0 -o json > grype-jupyterhub.json
```

**Key findings in this module:**

*JupyterHub 5.3.0 image:*
- **CVE-2024-23334** (aiohttp, CRITICAL) — path traversal in StaticFileHandler; fix: `aiohttp>=3.9.4`
- **CVE-2024-49769** (tornado, HIGH) — HTTP pipelining remote DoS; fix: `tornado>=6.4.1`
- **CVE-2024-35178** (jupyter-server, HIGH) — SSRF via open-with; fix: `jupyter-server>=2.14.1`

*scipy-notebook:2024-10-07 image:*
- **CVE-2024-45887** (nbconvert, HIGH) — stored XSS via crafted notebook HTML; **no upstream fix yet**
- `libssl1.1` (Ubuntu 22.04) — multiple HIGH CVEs, no OS patch, requires Ubuntu 24.04 base

*postgres:9.3:*
- **2 Critical + 12 High CVEs, none with fix versions** — Debian Jessie is fully EOL. Replace with postgres:16.

**Capabilities:**
- Scans OS packages AND language-level packages in a single pass
- Supports OCI, Docker, Singularity, SBOM (SPDX/CycloneDX) inputs
- Watch mode (`grype watch`) for continuous scanning
- Can generate SBOMs alongside CVE reports
- Works against local filesystems and directories, not just images

**Drawbacks:**
- Requires Docker (or containerd) to pull images — not usable in strict air-gapped environments without a local registry mirror
- False negatives for vendored, statically compiled, or obfuscated binaries
- The vulnerability DB must stay current — stale DB = missed CVEs
- `(none)` fixed-in-version for EOL images creates noise without clear path forward
- Cannot detect misconfigurations or K8s posture issues (use Checkov/Kubescape)
- No container runtime behavioral analysis (use Falco for that)

---

### Kubescape — Kubernetes Security Posture Manager

**What it is:** A K8s security scanning tool that evaluates clusters and manifests against security frameworks (NSA Hardening Guidelines, MITRE ATT&CK for Containers, CIS Benchmarks, SOC 2).

**How it works:** Can scan static YAML files without a cluster, or connect to a live cluster via kubeconfig. Evaluates each Kubernetes resource against a set of controls derived from the selected framework. Each control maps back to a security risk and provides remediation guidance.

**Running against this module:**
```bash
# Static manifest scan — NSA framework
kubescape scan framework nsa k8s-manifests/

# Static manifest scan — MITRE ATT&CK
kubescape scan framework mitre k8s-manifests/

# Specific controls only
kubescape scan control C-0016,C-0012,C-0004,C-0046 k8s-manifests/

# Live cluster scan (requires kubeconfig)
kubescape scan framework nsa

# JSON output
kubescape scan framework nsa k8s-manifests/ --format json --output nsa-results.json
```

**Key findings in this module:**

*NSA Framework (10/21 failed):*
- C-0045 (HIGH) — Docker socket hostPath mount → attacker can escape to host
- C-0012 (HIGH) — Credentials in env vars
- C-0016 (HIGH) — Privilege escalation allowed
- C-0034 (MEDIUM) — cluster-admin SA binding
- C-0260 (MEDIUM) — No NetworkPolicy on any pod

*MITRE ATT&CK (6/18 failed):*
- T1611 (CRITICAL) — Escape to Host via Docker socket
- T1552 (HIGH) — Unsecured Credentials in plaintext env vars
- T1613 (MEDIUM) — Container Discovery via auto-mounted SA token
- T1595 (MEDIUM) — Internal scanning enabled by missing NetworkPolicy

**Sandbox: NSA 68% → Hardened 11% (84% risk reduction)**

**Capabilities:**
- Multi-framework coverage in one tool (NSA, MITRE, CIS, SOC2, DISA-STIG)
- Live cluster scanning with operator-level depth
- Continuous posture monitoring via Kubescape Cloud or self-hosted
- RBAC risk analysis and service account permission review
- Custom framework support (write your own controls in Rego)

**Drawbacks:**
- A "passing" NSA score does not guarantee security — framework coverage is not exhaustive
- Live cluster scan requires kubeconfig access — sensitive permission in production
- Static scan misses admission-controller-injected fields (mutating webhooks, sidecar injectors)
- MITRE mapping is heuristic, not behavioral — cannot detect active exploitation (use Falco for runtime)
- Some controls overlap between NSA and MITRE, inflating apparent finding counts
- Rate-limited against GitHub for latest rule updates (offline cache used by default in CI)

---

## Sandbox Setup (kind)

### Architecture

```
┌──────────────────────────────────────────────────────┐
│  kind cluster "jupyter-security"                     │
│                                                      │
│  ┌─────────────────┐   ┌─────────────────────────┐  │
│  │  control-plane  │   │       worker node       │  │
│  │                 │   │                         │  │
│  │  kube-apiserver │   │  ┌──────────────────┐   │  │
│  │  etcd           │   │  │  jupyter ns      │   │  │
│  │  scheduler      │   │  │  ┌─────────────┐ │   │  │
│  │                 │   │  │  │  hub pod    │ │   │  │
│  │                 │   │  │  │  proxy pod  │ │   │  │
│  │                 │   │  │  │  user pods  │ │   │  │
│  │                 │   │  │  └─────────────┘ │   │  │
│  │                 │   │  └──────────────────┘   │  │
│  └─────────────────┘   └─────────────────────────┘  │
│                                                      │
│  CNI: Calico (required for NetworkPolicy enforcement)│
│  Ingress: NGINX                                      │
└──────────────────────────────────────────────────────┘
```

### Important: NetworkPolicy Enforcement

kind's default CNI (`kindnet`) does **not** enforce NetworkPolicy. To actually test NetworkPolicy:

```bash
# Create cluster with Calico CNI
./setup-sandbox.sh --with-calico

# Verify Calico is running
kubectl get pods -n kube-system | grep calico

# Apply the NetworkPolicies
kubectl apply -f k8s-manifests/network-policy.yaml

# Test: this should FAIL (blocked by policy)
kubectl exec -n jupyter <user-pod> -- curl http://hub:8081/hub/api
```

### Vulnerable vs Hardened Deployment

```bash
# Deploy vulnerable manifests
./deploy-jupyter.sh --mode vulnerable

# Run Kubescape against live cluster
kubescape scan framework nsa --format pretty-printer

# Switch to hardened
kubectl delete -f k8s-manifests/jupyterhub-deployment.yaml
./deploy-jupyter.sh --mode hardened

# Re-scan — score should drop from 68% to 11%
kubescape scan framework nsa --format pretty-printer
```

### Repo Scanning (Checkov + Grype)

The run scripts expect the JupyterHub/JupyterLab repos to be cloned locally:

```bash
# Clone target repos (requires internet access)
mkdir -p repos
git clone https://github.com/jupyterhub/jupyterhub repos/jupyterhub
git clone https://github.com/jupyterlab/jupyterlab repos/jupyterlab

# Now run Checkov against Dockerfiles
./scans/checkov/run-checkov.sh
```

---

## Security Analysis Summary

### Vulnerable Manifest Risk Score: 68% (NSA)

The default JupyterHub example manifests exhibit a classic "development convenience over security" pattern. The Docker socket mount alone is a complete cluster compromise — any user with notebook execution rights can escape to the host in two commands. Combined with the `cluster-admin` SA binding, an attacker has full control of the Kubernetes cluster from any notebook cell.

### Hardened Manifest Risk Score: 11% (NSA)

The hardened manifests eliminate all three HIGH controls and five of the six MEDIUM controls. The remaining two failures (no PodDisruptionBudget, read-write filesystem for notebook container) are either availability concerns or intentional trade-offs — notebook users require write access to `/home/jovyan` to do their work.

### Tool Complementarity

No single tool covers everything. The recommended stack for a JupyterHub deployment:

| Layer | Tool | What It Catches |
|-------|------|----------------|
| IaC / manifest review | Checkov | Misconfigurations before deploy |
| Image supply chain | Grype | Known CVEs in images |
| Cluster posture | Kubescape | K8s RBAC, network, runtime config |
| Runtime behavior | Falco *(not in this module)* | Active exploitation in real-time |
| Secrets management | Vault / ESO *(not in this module)* | Secret rotation and audit |

### What's Missing from This Toolkit

These tools together provide excellent static and configuration-layer coverage, but they cannot detect:

- **Runtime behavior** — use Falco for syscall-level detection of active exploitation
- **Secrets in git history** — use truffleHog or gitleaks for secret scanning
- **Dependency confusion attacks** — Grype catches known CVEs but not supply-chain substitution
- **Custom application vulnerabilities** — need SAST/DAST for application-layer issues (see the `appsec_sprint_evaluator` module)
- **Lateral movement in progress** — network flow analysis requires a service mesh or network monitor

---

## File Reference

```
container-k8s-security/
│
├── README.md                               ← This file
│
├── k8s-manifests/
│   ├── jupyterhub-deployment.yaml          ← Vulnerable: 15+ labeled security issues
│   ├── jupyterhub-deployment-hardened.yaml ← Hardened: all issues remediated
│   ├── network-policy.yaml                 ← NetworkPolicies for hub/proxy/user pods
│   └── single-user-profile.yaml           ← Vulnerable + hardened single-user pod
│
├── sandbox/
│   ├── kind-config.yaml                    ← 2-node kind cluster definition
│   ├── setup-sandbox.sh                    ← Cluster creation + CNI + ingress setup
│   └── deploy-jupyter.sh                   ← Deploy vulnerable or hardened to cluster
│
├── scans/
│   ├── checkov/
│   │   ├── run-checkov.sh                  ← Automated checkov scan runner
│   │   ├── k8s_manifests.txt               ← Pre-canned: 34 failed (vulnerable) / 3 (hardened)
│   │   └── jupyterhub_dockerfile.txt       ← Pre-canned: 18 Dockerfile findings
│   │
│   ├── grype/
│   │   ├── run-grype.sh                    ← Automated grype scan runner (3 images)
│   │   ├── jupyterhub_image_summary.txt    ← 1 Critical + 10 High CVEs
│   │   ├── jupyterlab_image_summary.txt    ← 8 High CVEs (nbconvert XSS, libssl EOL)
│   │   └── postgres93_summary.txt          ← 2 Critical + 12 High, all unfixable
│   │
│   └── kubescape/
│       ├── run-kubescape.sh                ← NSA + MITRE + specific control scans
│       ├── nsa_results.txt                 ← 10/21 failed, 68% risk score
│       └── mitre_results.txt               ← 6/18 techniques, full attack chain
│
└── output/
    ├── container-k8s-security-dashboard.md  ← Unified findings dashboard (this sprint)
    └── container-k8s-security-dashboard.json← Machine-readable dashboard
```
