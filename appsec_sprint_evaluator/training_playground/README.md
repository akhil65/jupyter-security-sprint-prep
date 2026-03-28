# Training Playground

This directory contains intentionally vulnerable files used to verify that the `appsec_sprint_evaluator` pipeline can detect known security issues. Run the evaluator against `training_playground` to confirm each scanner stage is working before pointing it at real Jupyter repos.

## What's Inside

**`vulnerable_app.py`** — Python file with deliberate SAST findings: a `subprocess.Popen(shell=True)` command injection, a `pickle.loads()` insecure deserialization, and a hardcoded fake AWS key. Bandit and semgrep should catch the first two; the secrets scanner stub demonstrates the key detection pattern.

**`requirements.txt`** — Pins `requests==2.28.1` and `urllib3<1.26.17`, both below the versions that fix known CVEs (CVE-2023-32681, CVE-2023-43804). pip-audit should flag these.

**`main.tf`** — Terraform config declaring a publicly readable S3 bucket using the deprecated `acl = "public-read"` argument. The IaC scanner stub demonstrates what Trivy or Checkov would flag here.

## What's Actually Integrated vs Stubbed

The evaluator has two modes:

| Stage | Tool | Status |
|-------|------|--------|
| SAST | bandit + semgrep | ✅ Fully integrated — reads real JSON from `scans/` |
| SCA | pip-audit | ✅ Fully integrated — reads real JSON from `scans/pip-audit/` |
| Secrets | gitleaks / trufflehog | 🔧 Stub — returns training demo finding only |
| IaC | trivy / checkov | 🔧 Stub — returns training demo finding only |
| AI-SPM | nb-defense | 🔧 Stub — returns training demo finding only |
| DAST | jupyter server probe | ✅ Implemented — spins up local Jupyter Server, checks `/api/kernels` auth and security headers |
| AI Triage | Gemini / mock | ✅ Implemented — mock mode always available, Gemini requires API key |

## Running the Tutorial

```bash
appsec-tutorial
```

This walks through each pipeline stage against the training playground files, showing what each scanner finds and how the results flow through triage to a draft PR.

## Running the Evaluator Directly

```bash
appsec-eval --target-repo training_playground
```

To run against real Jupyter repos (after running the scan scripts):

```bash
appsec-eval --target-repo jupyter_server
appsec-eval --target-repo jupyterhub
```
