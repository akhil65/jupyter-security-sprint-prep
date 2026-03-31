# Container & Kubernetes Security Dashboard
## JupyterHub / JupyterLab Security Analysis
**Scan Date:** 2026-03-31
**Tools:** Checkov 3.2.0 · Grype (latest DB) · Kubescape 3.x
**Targets:** K8s manifests · Container images · JupyterHub Dockerfiles

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total IaC checks failed (vulnerable manifests) | 34 |
| Total IaC checks passed (hardened manifests) | 28 / 31 |
| IaC risk reduction (hardened vs vulnerable) | **91%** |
| Container CVEs — Critical | 3 (2 in postgres:9.3, 1 in jupyterhub:5.3.0) |
| Container CVEs — High | 30 (across all 3 images) |
| NSA Hardening controls failed | 10 / 21 |
| MITRE ATT&CK techniques failed | 6 / 18 |
| NSA risk score (vulnerable) | 68% |
| NSA risk score (hardened) | 11% — **84% reduction** |

**Overall assessment:** The default/example JupyterHub deployment configuration has critical security gaps that enable full host compromise via the Docker socket mount. The hardened manifests address all critical and high findings, reducing the risk score from 68% to 11%.

---

## 1. Checkov — IaC Static Analysis

### 1a. K8s Manifests

| Severity | Finding | Resource | CKV ID |
|----------|---------|----------|--------|
| 🔴 CRITICAL | Docker socket mounted — full container escape | hub | CKV_K8S_25 |
| 🔴 CRITICAL | cluster-admin ClusterRoleBinding | jupyterhub-admin | CKV_K8S_41 |
| 🔴 CRITICAL | Wildcard permissions in ClusterRole | jupyterhub-admin | CKV_K8S_49 |
| 🟠 HIGH | Hardcoded secrets in env vars (crypt key + DB pass) | hub | CKV_K8S_35 |
| 🟠 HIGH | Container runs as root (runAsNonRoot: false) | hub, user pod | CKV_K8S_6 |
| 🟠 HIGH | allowPrivilegeEscalation: true | hub | CKV_K8S_20 |
| 🟡 MEDIUM | No CPU/memory limits — DoS risk | hub, proxy, user pod | CKV_K8S_10–13 |
| 🟡 MEDIUM | No NetworkPolicy defined | all pods | CKV_K8S_7 |
| 🟡 MEDIUM | :latest unpinned image tags | hub, proxy, user pod | CKV_K8S_14 |
| 🟡 MEDIUM | No securityContext defined | proxy, user pod | CKV_K8S_30 |
| 🟡 MEDIUM | NET_ADMIN capability added | hub | CKV_K8S_36 |
| 🟡 MEDIUM | automountServiceAccountToken: true | user pod | CKV_K8S_41 |
| 🟢 LOW | readOnlyRootFilesystem: false | hub, proxy, user pod | CKV_K8S_22 |
| 🟢 LOW | No liveness/readiness probes | hub, proxy, user pod | CKV_K8S_8/9 |
| 🟢 LOW | Image not pinned by digest | hub, proxy | CKV_K8S_43 |

**Vulnerable total: 34 failed / 40 checks**
**Hardened total: 3 failed / 31 checks** (remaining: no digest pin, no PDB, placeholder secrets)

### 1b. Dockerfiles (JupyterHub repo)

| Severity | Finding | Dockerfile | CKV ID |
|----------|---------|-----------|--------|
| 🔴 CRITICAL | Base image postgres:9.3 is EOL (Debian Jessie) | examples/postgres | CKV2_DOCKER_3 |
| 🟠 HIGH | No USER directive — runs as root | service-fastapi | CKV_DOCKER_3 |
| 🟠 HIGH | Hardcoded password in RUN command | examples/postgres | CKV_DOCKER_4/17 |
| 🟡 MEDIUM | No HEALTHCHECK | all 3 Dockerfiles | CKV_DOCKER_2 |
| 🟡 MEDIUM | :latest base image tag | examples | CKV_DOCKER_7 |

---

## 2. Grype — Container Image CVE Scan

### 2a. quay.io/jupyterhub/jupyterhub:5.3.0

**Base OS:** Debian 12 (Bookworm) · 312 packages scanned
**11 actionable findings (Critical + High), all have fix versions**

| CVE | Package | Installed | Fixed In | Severity | Description |
|-----|---------|-----------|----------|----------|-------------|
| CVE-2024-23334 | aiohttp | 3.9.3 | 3.9.4 | 🔴 CRITICAL | Path traversal in StaticFileHandler |
| CVE-2024-49769 | tornado | 6.4 | 6.4.1 | 🟠 HIGH | Remote DoS via HTTP pipelining |
| CVE-2024-35178 | jupyter-server | 2.13.0 | 2.14.1 | 🟠 HIGH | SSRF via open-with mechanism |
| CVE-2024-56201 | jinja2 | 3.1.3 | 3.1.5 | 🟠 HIGH | Template sandbox escape |
| CVE-2024-26130 | cryptography | 42.0.4 | 42.0.6 | 🟠 HIGH | NULL ptr deref in PKCS12 parsing |
| CVE-2024-42367 | aiohttp | 3.9.3 | 3.10.11 | 🟠 HIGH | Additional aiohttp vuln |
| CVE-2024-6345 | setuptools | 69.1.1 | 70.0.0 | 🟠 HIGH | Code injection in package metadata |
| CVE-2024-5535 | libssl3 | 3.0.11 | 3.0.15 | 🟠 HIGH | OpenSSL read buffer overrun |
| CVE-2024-28757 | libexpat1 | 2.5.0 | 2.6.0 | 🟠 HIGH | XML DoS via billion laughs |
| GHSA-5h86-8mv2 | aiohttp | 3.9.3 | 3.9.4 | 🟠 HIGH | CRLF injection in request headers |
| CVE-2024-28219 | pillow | 10.2.0 | 10.3.0 | 🟠 HIGH | Buffer overflow in ImageCms |

**Summary:** 1 Critical, 10 High, 15 Medium. All critical/high have available fixes via pip upgrades.

### 2b. quay.io/jupyter/scipy-notebook:2024-10-07

**Base OS:** Ubuntu 22.04 (Jammy) · 847 packages scanned
**No Critical; 8 High**

| CVE | Package | Installed | Fixed In | Severity | Description |
|-----|---------|-----------|----------|----------|-------------|
| CVE-2024-45887 | nbconvert | 7.16.4 | *(none)* | 🟠 HIGH | Stored XSS via crafted notebook HTML |
| CVE-2024-49769 | tornado | 6.4 | 6.4.1 | 🟠 HIGH | Remote DoS via HTTP pipelining |
| CVE-2024-56201 | jinja2 | 3.1.4 | 3.1.5 | 🟠 HIGH | Template sandbox escape |
| CVE-2024-42367 | aiohttp | 3.9.5 | 3.10.11 | 🟠 HIGH | Path traversal |
| CVE-2024-6345 | setuptools | 72.1.0 | 75.0.0 | 🟠 HIGH | Code injection |
| CVE-2023-5363 | libssl1.1 | 1.1.1f | *(none)* | 🟠 HIGH | OpenSSL — OS-level, no patch |
| CVE-2024-5535 | libssl1.1 | 1.1.1f | *(none)* | 🟠 HIGH | OpenSSL — OS-level, no patch |

**Note on CVE-2024-45887 (nbconvert):** No upstream fix as of scan date. Mitigation: serve HTML output behind strict CSP; do not expose nbconvert API publicly.
**Note on libssl1.1:** Ubuntu 22.04's libssl1.1 reached EOL upstream — no patch available. Requires base image upgrade to Ubuntu 24.04.

### 2c. postgres:9.3 (used in JupyterHub examples)

**Base OS:** Debian 8 Jessie — EOL June 2020
**2 Critical, 12 High — NONE have fix versions**

| CVE | Package | Severity | Description |
|-----|---------|----------|-------------|
| CVE-2023-5363 | openssl 1.0.1t | 🔴 CRITICAL | CBC padding oracle |
| CVE-2023-5363 | libssl1.0.0 1.0.1t | 🔴 CRITICAL | (same, libssl copy) |
| CVE-2022-4304 | openssl | 🟠 HIGH | Timing oracle in RSA decryption |
| CVE-2022-4450 | openssl | 🟠 HIGH | Double-free in PEM parsing |
| CVE-2023-0286 | openssl | 🟠 HIGH | X.400 GeneralName type confusion |
| CVE-2024-0985 | postgresql-9.3 | 🟠 HIGH | Late-binding in row security policy |
| CVE-2023-2455 | postgresql-9.3 | 🟠 HIGH | Row security bypass via extension |
| CVE-2019-1010022 | libc6 | 🟠 HIGH | Stack-clash protection bypass |
| CVE-2019-9169 | libc6 | 🟠 HIGH | Buffer read OOB in regex |
| CVE-2023-5981 | libgnutls | 🟠 HIGH | Timing oracle in RSA-PSK |
| CVE-2021-33560 | libgcrypt20 | 🟠 HIGH | ECDH timing side channel |
| CVE-2023-27535 | curl | 🟠 HIGH | FTP credential auth bypass |

**Recommendation:** Replace `FROM postgres:9.3` with `FROM postgres:16` (or latest LTS). This is the single highest-priority Dockerfile fix in the JupyterHub repo.

---

## 3. Kubescape — K8s Posture Scanning

### 3a. NSA Hardening Framework

**Controls tested:** 21 · **Controls failed (vulnerable):** 10 · **Risk score:** 68%
**Controls failed (hardened):** 2 · **Risk score:** 11% · **Reduction:** 84%

| Control | Severity | Status | Description |
|---------|----------|--------|-------------|
| C-0045 | 🔴 HIGH | FAILED | Writable hostPath — Docker socket mounted |
| C-0012 | 🔴 HIGH | FAILED | Credentials in configuration files (env vars) |
| C-0016 | 🔴 HIGH | FAILED | Allow privilege escalation (hub + proxy) |
| C-0004 | 🟡 MEDIUM | FAILED | Missing resource limits (4 containers) |
| C-0021 | 🟡 MEDIUM | FAILED | automountServiceAccountToken on user pod |
| C-0034 | 🟡 MEDIUM | FAILED | cluster-admin ClusterRoleBinding |
| C-0046 | 🟡 MEDIUM | FAILED | NET_ADMIN capability added |
| C-0055 | 🟡 MEDIUM | FAILED | No seccomp/AppArmor profile |
| C-0260 | 🟡 MEDIUM | FAILED | Missing NetworkPolicy (3 pods) |
| C-0017 | 🟢 LOW | FAILED | readOnlyRootFilesystem: false |

**Remaining in hardened:** C-0043 (no PodDisruptionBudget — availability, not security) and C-0017 for notebook container (intentional — notebooks require write access to /home/jovyan).

### 3b. MITRE ATT&CK for Containers

**Techniques tested:** 18 · **Techniques failed (vulnerable):** 6 · **Techniques failed (hardened):** 0

| Technique | Tactic | Severity | Finding |
|-----------|--------|----------|---------|
| T1611 — Escape to Host | Privilege Escalation | 🔴 CRITICAL | Docker socket → full host root |
| T1610 — Deploy Container | Execution | 🟠 HIGH | cluster-admin SA enables new pod spawn |
| T1552 — Unsecured Credentials | Credential Access | 🟠 HIGH | Plaintext secrets in env vars |
| T1613 — Container Discovery | Discovery | 🟡 MEDIUM | SA token enables K8s API enumeration |
| T1595 — Active Scanning | Lateral Movement | 🟡 MEDIUM | No NetworkPolicy — free lateral movement |
| T1496 — Resource Hijacking | Impact | 🟡 MEDIUM | No limits — cryptomining / DoS possible |

**Worst-case attack chain:**
```
CVE in notebook package → RCE via pickle/deserialization
    → Enumerate cluster via SA token (T1613)
    → Read plaintext POSTGRES_PASSWORD (T1552)
    → Docker socket → privileged container (T1611)
    → Cloud metadata endpoint → IAM credential theft
    → Persist backdoor / exfil / cryptomine (T1496)
```

---

## 4. Tool Comparison

| Capability | Checkov | Grype | Kubescape |
|-----------|---------|-------|-----------|
| **Primary target** | IaC files (YAML, Dockerfile, Terraform) | Container images | Live/static K8s clusters |
| **What it finds** | Misconfigurations, hardcoding, policy violations | Known CVEs in OS + Python packages | K8s security posture against frameworks |
| **Frameworks** | CIS, NSA, NIST, PCI-DSS, SOC2 | NVD, GitHub Advisories, OSV | NSA, MITRE ATT&CK, CIS, SOC2 |
| **Fix guidance** | Specific CKV code + link to fix | Fixed-in version (when available) | Remediation steps + YAML snippets |
| **CI integration** | Excellent (GitHub Actions, GitLab CI) | Good (image scanning in pipeline) | Good (scan on cluster drift) |
| **False positive rate** | Low–Medium | Low (CVE-based) | Low–Medium |
| **Live cluster scan** | ✗ (static only) | ✗ (image only) | ✓ (live cluster via kubeconfig) |
| **Runtime detection** | ✗ | ✗ | ✗ (posture only, not runtime) |
| **Speed** | Fast (seconds) | Medium (image pull + scan) | Medium (depends on cluster size) |
| **Open source** | ✓ | ✓ | ✓ |

### Tool Drawbacks & Limitations

**Checkov**
- Scans manifest intent, not runtime state — a misconfiguration might be overridden by an admission controller
- Cannot detect image-level CVEs or runtime behavior
- Some CKV checks are noisy for legitimate use cases (e.g. CKV_K8S_43 digest pinning is impractical for many orgs)
- No visibility into what's actually running in the cluster

**Grype**
- Requires Docker to pull images — not usable in air-gapped environments without extra setup
- CVE database must be kept current (`grype db update`) or scan results become stale
- False negatives possible for vendored or statically compiled binaries
- Cannot detect misconfigurations — only known CVEs
- The `(none)` fix-in-version for EOL packages creates noise without clear remediation path

**Kubescape**
- NSA/MITRE coverage is good but not exhaustive — a passing score does not mean the cluster is secure
- Live cluster scan requires kubeconfig access — sensitive in production environments
- Static manifest scan misses admission-controller-injected fields (e.g. injected sidecars, mutating webhooks)
- MITRE technique mapping is heuristic — cannot detect actual exploitation in progress (use Falco for that)
- Some controls overlap between NSA and MITRE frameworks causing apparent duplication in reports

---

## 5. Remediation Priority

| Priority | Action | Tool(s) | Effort |
|----------|--------|---------|--------|
| P0 — Immediate | Remove Docker socket mount from hub deployment | Checkov / Kubescape | Low (delete 2 lines) |
| P0 — Immediate | Replace cluster-admin binding with minimal Role | Checkov / Kubescape | Medium |
| P0 — Immediate | Move secrets to K8s Secrets + secretKeyRef | Checkov / Kubescape | Medium |
| P0 — Immediate | Upgrade postgres:9.3 → postgres:16 | Grype | Low |
| P1 — This sprint | Set runAsNonRoot: true + allowPrivilegeEscalation: false | Checkov | Low |
| P1 — This sprint | Apply NetworkPolicy (hub, proxy, single-user) | Kubescape | Medium |
| P1 — This sprint | Upgrade aiohttp ≥ 3.9.4 (CVE-2024-23334 CRITICAL) | Grype | Low |
| P1 — This sprint | Upgrade tornado ≥ 6.4.1 (CVE-2024-49769) | Grype | Low |
| P2 — Next sprint | Pin all image tags to SHA256 digests | Checkov | Medium |
| P2 — Next sprint | Add resource limits to all containers | Checkov / Kubescape | Low |
| P2 — Next sprint | Add seccomp profile: RuntimeDefault | Kubescape | Low |
| P2 — Next sprint | Upgrade scipy-notebook base to Ubuntu 24.04 | Grype | High |
| P3 — Backlog | Add liveness/readiness probes | Checkov | Low |
| P3 — Backlog | Add PodDisruptionBudget for HA | Kubescape | Low |

---

## 6. Files in This Module

```
container-k8s-security/
├── README.md                          ← This module's full guide
├── k8s-manifests/
│   ├── jupyterhub-deployment.yaml     ← Intentionally vulnerable (15+ issues labeled)
│   ├── jupyterhub-deployment-hardened.yaml  ← Hardened reference manifest
│   ├── network-policy.yaml            ← NetworkPolicy for all pods
│   └── single-user-profile.yaml      ← Vulnerable + hardened single-user pod
├── sandbox/
│   ├── kind-config.yaml               ← 2-node kind cluster config
│   ├── setup-sandbox.sh               ← Creates cluster + installs prerequisites
│   └── deploy-jupyter.sh              ← Deploys vulnerable or hardened manifests
├── scans/
│   ├── checkov/
│   │   ├── run-checkov.sh             ← Run checkov against all targets
│   │   ├── k8s_manifests.txt          ← Pre-canned K8s manifest scan results
│   │   └── jupyterhub_dockerfile.txt  ← Pre-canned Dockerfile scan results
│   ├── grype/
│   │   ├── run-grype.sh               ← Run grype against all 3 images
│   │   ├── jupyterhub_image_summary.txt
│   │   ├── jupyterlab_image_summary.txt
│   │   └── postgres93_summary.txt
│   └── kubescape/
│       ├── run-kubescape.sh           ← Run kubescape NSA + MITRE scans
│       ├── nsa_results.txt            ← Pre-canned NSA framework results
│       └── mitre_results.txt          ← Pre-canned MITRE ATT&CK results
└── output/
    ├── container-k8s-security-dashboard.md   ← This file
    └── container-k8s-security-dashboard.json ← Machine-readable version
```
