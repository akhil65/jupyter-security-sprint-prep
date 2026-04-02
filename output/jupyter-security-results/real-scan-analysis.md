# JupyterHub K8s Security Analysis — Real Scan Results
**Scan date:** 2026-04-02
**Source:** Actual tool runs on your machine
**Tools:** Grype · Checkov · Kubescape
**Targets:** quay.io/jupyterhub/jupyterhub:5.3.0 · quay.io/jupyter/scipy-notebook:2024-10-07 · postgres:9.3 · z2jh Helm chart v3.3.7

---

## Executive Summary

| Target | Tool | Critical | High | Verdict |
|--------|------|----------|------|---------|
| jupyterhub:5.3.0 | Grype | 0 | 22 | Upgrade urllib3, tornado, cryptography |
| scipy-notebook:2024-10-07 | Grype | 2 | 48 | **Needs immediate attention** — h11 critical, Python vulns |
| postgres:9.3 | Grype | 157 | 319 | **Replace entirely** — 948 CVEs, 423 with no fix |
| z2jh Helm chart v3.3.7 | Checkov | — | — | 113 failed / 666 checks (17% fail rate) |
| z2jh Helm chart v3.3.7 | Kubescape NSA | — | — | **76.9%** compliance — 6 controls failed |
| z2jh Helm chart v3.3.7 | Kubescape MITRE | — | — | **87.6%** compliance — 4 controls failed |

---

## 1. Grype — quay.io/jupyterhub/jupyterhub:5.3.0

**482 CVEs total: 0 Critical · 22 High · 281 Medium · 175 Low**

No critical CVEs — this is the healthiest of the three images. All 22 High findings have fix versions available, making this straightforwardly actionable.

### High severity — actionable now

| CVE / GHSA | Package | Installed | Fix | Description |
|------------|---------|-----------|-----|-------------|
| CVE-2023-44487 | nodejs / libnode72 | 12.22.9 | none in this image | HTTP/2 Rapid Reset DDoS — Node.js bundled in Ubuntu base |
| CVE-2025-68973 | gnupg suite (10 pkgs) | 2.2.27-3ubuntu2.4 | 2.2.27-3ubuntu2.5 | GnuPG vulnerability — OS package update |
| GHSA-qjxf-f2mg-c6mc | tornado | 6.5.2 | 6.5.5 | HTTP request smuggling |
| GHSA-gm62-xv2j-4w53 | urllib3 | 2.5.0 | 2.6.0 | Proxy header injection |
| GHSA-2xpw-w6gg-jr37 | urllib3 | 2.5.0 | 2.6.0 | Redirect handling flaw |
| GHSA-38jv-5279-wg99 | urllib3 | 2.5.0 | 2.6.3 | Request smuggling |
| GHSA-r6ph-v2qm-q3c2 | cryptography | 46.0.2 | 46.0.5 | Memory corruption |
| GHSA-8rrh-rw8j-w5fx | wheel | 0.45.1 | 0.46.2 | ReDoS in wheel parsing |
| GHSA-58pv-8j8x-9vj2 | jaraco-context | 5.3.0 | 6.1.0 | Arbitrary code execution |
| GHSA-rc47-6667-2j5j | http-cache-semantics | 4.1.0 | 4.1.1 | ReDoS |

**Node.js note:** CVE-2023-44487 (Rapid Reset) has no fix for the Ubuntu-packaged nodejs 12.22.9 because Node 12 is EOL. It's a transitive Ubuntu package — not something JupyterHub uses directly. The hub itself runs Python, not Node.

**Fix these in one command:**
```bash
pip install --upgrade tornado urllib3 cryptography wheel "jaraco.context>=6.1.0"
```

---

## 2. Grype — quay.io/jupyter/scipy-notebook:2024-10-07

**1,540 CVEs total: 2 Critical · 48 High · 1,189 Medium · 254 Low**

This is the single-user notebook image — the one that runs user code. It has the largest attack surface (847 packages) and the most critical findings. The 2 Critical CVEs need immediate remediation.

### Critical severity

| CVE / GHSA | Package | Installed | Fix | Description |
|------------|---------|-----------|-----|-------------|
| **GHSA-vqfr-h8mv-ghfj** | **h11** | **0.14.0** | **0.16.0** | **HTTP/1.1 parser — request smuggling, affects httpx and Jupyter's internal HTTP** |
| **CVE-2025-4517** | **python** | **3.11.10** | **3.9.23*** | **Python path traversal / arbitrary code via tarfile** |

*Note on CVE-2025-4517 fix version: Grype shows 3.9.23 because the CVE DB indexed the fix on the 3.9 branch. The actual fix for 3.11 is Python 3.11.13+ — upgrade the base image to get this.

**h11 is the higher-risk finding.** It's the HTTP library underpinning `httpx`, which Jupyter Server and JupyterHub use for internal API calls. A request smuggling attack can allow one user's request to be interpreted as another user's, potentially accessing other notebooks or admin endpoints.

### High severity — selected notable findings

| CVE / GHSA | Package | Installed | Fix | Description |
|------------|---------|-----------|-----|-------------|
| GHSA-xm59-rqc7-hhvf | **nbconvert** | 7.16.4 | **7.17.0** | XSS via crafted notebook HTML output *(fix now exists — previous pre-scan estimate was wrong)* |
| GHSA-cj5w-8mjf-r5f8 | **jupyterlab-git** | 0.50.1 | 0.51.1 | Arbitrary code execution |
| GHSA-33p9-3p43-82vq | **jupyter-core** | 5.7.2 | 5.8.1 | Path traversal in config loading |
| GHSA-7cx3-6m66-7c5m | tornado | 6.4.1 | 6.5 | HTTP DoS |
| GHSA-8w49-h785-mj3c | tornado | 6.4.1 | 6.4.2 | Websocket memory exhaustion |
| GHSA-qjxf-f2mg-c6mc | tornado | 6.4.1 | 6.5.5 | Request smuggling |
| GHSA-752w-5fwx-jx9f | pyjwt | 2.9.0 | 2.12.0 | Algorithm confusion attack |
| GHSA-r6ph-v2qm-q3c2 | cryptography | 43.0.1 | 46.0.5 | Memory corruption |
| GHSA-5rjg-fvgr-3xxf | setuptools | 75.1.0 | 78.1.1 | Code injection via package metadata |
| CVE-2025-32463 | sudo | 1.9.15p5-3ubuntu5 | patch available | Privilege escalation |
| CVE-2025-48384 | git | 2.43.0 | patch available | Remote code execution |
| GHSA-cfh3-3jmp-rvhc | pillow | 10.4.0 | 12.1.1 | Buffer overflow in image processing |
| GHSA-2qfp-q593-8484 | brotli | 1.1.0 | 1.2.0 | Memory corruption |
| CVE-2026-4519 | python | 3.11.10 | none | Unfixed Python vulnerability |

**Fix these in one command:**
```bash
pip install --upgrade \
  h11 nbconvert jupyterlab-git jupyter-core \
  tornado pyjwt cryptography setuptools pillow brotli
```

**Important correction from pre-scan estimates:** nbconvert XSS (GHSA-xm59-rqc7-hhvf) now has a fix in 7.17.0. The pre-canned estimate said no fix existed — the real scan shows it does.

---

## 3. Grype — postgres:9.3

**948 CVEs total: 157 Critical · 319 High · 245 Medium · 79 Low**
**423 CVEs have no fix version. 525 have fixes but the OS is EOL.**

This image (used in the JupyterHub `examples/postgres/` directory) is built on **Debian 8 Jessie, which reached end-of-life in June 2020**. Every single CVE is either unfixable or would require patches that no longer receive security updates.

### Why 157 Critical CVEs?

The critical count is inflated because each vulnerable *package* counts as a separate finding — for example, the `libc6` critical appears 5 times (for `libc-bin`, `libc-l10n`, `libc6`, `locales`, `multiarch-support`). The distinct critical vulnerabilities are fewer but still severe:

| CVE | Package | Fix | Description |
|-----|---------|-----|-------------|
| CVE-2022-2274 | openssl / libssl1.1 | **none** | Heap memory corruption in RSA private key operations |
| CVE-2022-2068 | openssl / libssl1.1 | **none** | Command injection via c_rehash script |
| CVE-2019-9169 | libc6 (glibc) | **none** | Buffer read OOB in regex — remote code execution |
| CVE-2021-35942 | libc6 (glibc) | **none** | Integer overflow in wordexp() |
| CVE-2022-23218/9 | libc6 (glibc) | **none** | Buffer overflow in svcunix_create |
| CVE-2018-6485/6551 | libc6 (glibc) | **none** | Integer overflow in posix_memalign |
| CVE-2015-20107 | python 3.5 | **none** | Mailcap command injection |
| CVE-2019-8457 | libsqlite3 | **none** | Heap OOB read in rtreenode() |
| CVE-2019-10149 | exim4 | fix exists (deb9u4) | Remote command execution in SMTP |
| CVE-2020-28020/22/24/26 | exim4 | fix exists (deb9u8) | Multiple RCE in Exim mail server |

**The only correct remediation is replacing the entire image:**
```dockerfile
# Before
FROM postgres:9.3

# After
FROM postgres:16
```

This is one line in `examples/postgres/db/Dockerfile`. Postgres 9.3 itself also reached end-of-life in November 2018 — over 7 years ago.

---

## 4. Checkov — z2jh Helm Chart v3.3.7

**553 passed · 113 failed · 17% fail rate**

These are real findings against the official JupyterHub Helm chart. This is what a default `helm install jupyterhub/jupyterhub` deploys.

### Failed checks by category

| Check ID | Count | Severity | Finding |
|----------|-------|----------|---------|
| CKV_K8S_21 | 20 | Medium | Resources deployed to **default namespace** |
| CKV_K8S_10 | 7 | High | **CPU requests not set** |
| CKV_K8S_11 | 7 | High | **CPU limits not set** |
| CKV_K8S_13 | 7 | High | **Memory limits not set** |
| CKV_K8S_12 | 6 | High | Memory requests not set |
| CKV_K8S_15 | 7 | Medium | ImagePullPolicy not Always |
| CKV_K8S_22 | 7 | Medium | Read-only root filesystem not enforced |
| CKV_K8S_28 | 7 | Medium | NET_RAW capability not dropped |
| CKV_K8S_31 | 7 | Medium | **Seccomp profile not set** |
| CKV_K8S_37 | 7 | Medium | Capabilities not minimised |
| CKV_K8S_43 | 7 | Low | Images not pinned to digest |
| CKV_K8S_29 | 6 | Medium | Security context not applied to pods |
| CKV2_K8S_6 | 5 | High | **5 pods lack NetworkPolicy** |
| CKV_K8S_38 | 4 | Medium | SA tokens mounted unnecessarily |
| CKV_K8S_8 | 3 | Medium | Liveness probe not configured |
| CKV_K8S_9 | 3 | Medium | Readiness probe not configured |
| CKV_K8S_35 | 2 | High | **Secrets exposed as env vars** |
| CKV_K8S_40 | 1 | Low | Container runs as low UID |

### What the chart does well (553 passing)

Notably passing — the chart is NOT vulnerable on these important controls:
- No privileged containers
- No hostPath mounts / no Docker socket
- No host network or host PID access
- No cluster-admin bindings
- Non-root containers enforced where possible
- RBAC properly scoped to namespace

### Key concern: CKV_K8S_21 — default namespace (20 failures)

The z2jh chart deploys the majority of its resources into the `default` namespace unless you override it at install time. This means JupyterHub resources share a namespace with anything else you've deployed without a namespace. **Always install with `--namespace jupyter --create-namespace`.**

### Key concern: CKV_K8S_35 — secrets as env vars (2 failures)

Two resources pass secrets via environment variables rather than mounted secret files. This exposes credentials via `kubectl describe pod` and `/proc/<pid>/environ`. Overrideable via Helm values.

---

## 5. Kubescape — NSA Hardening Framework

**Compliance score: 76.9% · 6 failed / 20 controls**

| Control | Severity | Finding | Impact |
|---------|----------|---------|--------|
| **C-0012** | High | Applications credentials in config files | Secrets exposed in env vars — same as CKV_K8S_35 |
| **C-0270** | High | CPU limits not set | Noisy-neighbour DoS — one user can starve the cluster |
| **C-0271** | High | Memory limits not set | OOM kill risk — no memory guardrails on user pods |
| C-0030 | Medium | Ingress and egress not blocked | No NetworkPolicy — pods can reach each other freely |
| C-0055 | Medium | Linux hardening missing | No seccomp profile / AppArmor annotations |
| C-0017 | Low | Mutable container filesystem | Containers can write to their own root filesystem |

### What the chart passes on NSA

These are the controls that matter most — and the z2jh chart passes all of them:

| Control | Finding |
|---------|---------|
| C-0016 | No privilege escalation allowed ✓ |
| C-0034 | Service account tokens not auto-mounted ✓ |
| C-0035 | No administrative (cluster-admin) roles ✓ |
| C-0045 | No writable hostPath mounts ✓ |
| C-0057 | No privileged containers ✓ |
| C-0046 | No dangerous capabilities ✓ |

The chart's default security posture is significantly better than a hand-crafted naive deployment. The 6 failures are real but lower-severity than the worst K8s security anti-patterns.

---

## 6. Kubescape — MITRE ATT&CK for Containers

**Compliance score: 87.6% · 4 failed / 17 controls**

| Control | Severity | MITRE Tactic | Finding |
|---------|----------|-------------|---------|
| **C-0012** | High | Credential Access | Credentials in config files |
| **C-0015** | High | Discovery | Roles allow listing K8s secrets |
| C-0007 | Medium | Impact | Roles with delete capabilities |
| C-0053 | Medium | Discovery | Container service account accessible |

### Attack path from real findings

The two High MITRE failures form a realistic chain: C-0053 means user pods can access the service account token → C-0015 means that SA can list secrets → C-0012 means some secrets are in env vars and thus also visible via pod describe. An attacker with notebook code execution could traverse this path to exfiltrate cluster credentials.

### What passes (notably)

- C-0045: No writable hostPath — host escape blocked ✓
- C-0057: No privileged containers ✓
- C-0035: No admin roles ✓
- C-0002: No exec access to containers via K8s API ✓
- C-0042: No SSH server in containers ✓

---

## Remediation Priority — Real Findings

| Priority | Action | Finding source | Effort |
|----------|--------|---------------|--------|
| **P0** | Replace `postgres:9.3` → `postgres:16` | Grype — 157 Critical | 1 line |
| **P0** | Upgrade `h11 >= 0.16.0` in scipy-notebook | Grype — Critical | pip upgrade |
| **P0** | Upgrade `tornado >= 6.5.5` in both images | Grype — High (both) | pip upgrade |
| **P0** | Upgrade `urllib3 >= 2.6.3` in jupyterhub | Grype — High (3 CVEs) | pip upgrade |
| **P1** | Upgrade `nbconvert >= 7.17.0` | Grype — High, fix exists | pip upgrade |
| **P1** | Upgrade `jupyterlab-git >= 0.51.1` | Grype — High | pip upgrade |
| **P1** | Upgrade `jupyter-core >= 5.8.1` | Grype — High | pip upgrade |
| **P1** | Upgrade scipy-notebook base image (Python 3.11 → latest 3.12+) | Grype — Critical Python CVEs | Image rebuild |
| **P1** | Deploy to dedicated namespace (`--namespace jupyter`) | Checkov — 20 failures | Helm flag |
| **P1** | Set resource limits/requests in Helm values | Checkov/Kubescape — 4 High | Helm values |
| **P1** | Apply NetworkPolicy (C-0030 / CKV2_K8S_6) | Kubescape/Checkov | K8s manifest |
| **P2** | Move secrets to mounted files not env vars (C-0012) | Kubescape/Checkov | Helm values |
| **P2** | Add seccomp profile `RuntimeDefault` (C-0055) | Kubescape | Helm values |
| **P2** | Restrict SA permissions to prevent secret listing (C-0015) | Kubescape | RBAC |
| **P3** | Pin images to SHA256 digests | Checkov | Helm values |
| **P3** | Enable read-only root filesystem | Checkov/Kubescape | Helm values |

---

## Corrections vs Pre-Scan Estimates

The real scans revealed two important differences from the pre-canned estimates:

1. **nbconvert XSS now has a fix.** The pre-canned estimate said `(none)` — the real Grype DB shows `nbconvert 7.17.0` fixes it. Upgrade immediately.
2. **scipy-notebook has 2 Critical CVEs, not 0.** The real scan found `h11` (GHSA-vqfr-h8mv-ghfj, Critical) and `CVE-2025-4517` (Python, Critical) — neither appeared in the pre-canned results because they are newer CVEs.
3. **postgres:9.3 is far worse than estimated.** Pre-canned said 2 Critical — real scan shows 157 Critical. The full EOL OS exposure is much larger than expected.
4. **z2jh Helm chart is better than the demo manifests.** The real chart passes all the most dangerous controls (no privileged containers, no Docker socket, no cluster-admin). The pre-canned demo manifests were intentionally broken to illustrate tool capabilities — not representative of what the real chart deploys.
