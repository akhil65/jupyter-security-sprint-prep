# Training Playground

This directory contains intentionally vulnerable files used to verify that the `appsec_sprint_evaluator` pipeline can detect known security issues. Run the evaluator against `training_playground` to confirm each scanner stage is working before pointing it at real Jupyter repos.

## What's Inside

**`vulnerable_app.py`** — Python file with deliberate SAST findings: a `subprocess.Popen(shell=True)` command injection, a `pickle.loads()` insecure deserialization, and a hardcoded fake AWS key. Bandit and semgrep should catch the first two; the secrets scanner stub demonstrates the key detection pattern.

**`requirements.txt`** — Pins `requests==2.28.1` and `urllib3<1.26.17`, both below the versions that fix known CVEs (CVE-2023-32681, CVE-2023-43804). pip-audit should flag these.

**`main.tf`** — Terraform config declaring an S3 bucket without an `aws_s3_bucket_public_access_block` resource, leaving the bucket publicly accessible. This is what Trivy/Checkov flag as AVD-AWS-0057 ("Bucket does not have public access block enabled"). The file also includes a commented-out legacy example using the deprecated `acl = "public-read"` argument (removed in AWS provider v5) for reference.

## What's Actually Integrated vs Stubbed

The evaluator has two modes:

| Stage | Tool | training_playground | Real repos (jupyter_server / jupyterhub) |
|-------|------|---------------------|------------------------------------------|
| SAST | bandit + semgrep | Pre-canned demo findings (no scan needed) | ✅ Reads real JSON from `scans/bandit/` and `scans/semgrep/` |
| SCA | pip-audit | Pre-canned demo finding (no scan needed) | ✅ Reads real JSON from `scans/pip-audit/` |
| Secrets | gitleaks / trufflehog | 🔧 Stub — returns demo finding only | 🔧 Stub — integrate CLI for real results |
| IaC | trivy / checkov | 🔧 Stub — returns demo finding only | 🔧 Stub — integrate CLI for real results |
| AI-SPM | nb-defense | 🔧 Stub — returns demo finding only | 🔧 Stub — integrate CLI for real results |
| DAST | jupyter server probe | ⏭ Skipped — no live server to probe | ✅ Spins up local Jupyter Server, checks `/api/kernels` auth and security headers |
| AI Triage | Gemini / mock | ✅ Mock mode always available | ✅ Mock always available, Gemini requires `GEMINI_API_KEY` |

## Installation

Install the evaluator from the `appsec_sprint_evaluator/` directory (or the project root):

```bash
pip install -e appsec_sprint_evaluator/
```

## Running the Tutorial

> **Important:** Run all commands from the **project root** (`jupyter-security-sprint-prep/`). The evaluator resolves `scans/`, `notes/`, and `output/` as relative paths from your working directory — running from a subdirectory will cause silent scan misses.

```bash
# From the project root:
appsec-tutorial
```

This walks through each pipeline stage against the training playground files, showing what each scanner finds and how the results flow through triage to a draft PR.

## Running the Evaluator Directly

```bash
# From the project root:
appsec-eval --target-repo training_playground
```

To run against real Jupyter repos (after running the scan scripts in `scans/`):

```bash
appsec-eval --target-repo jupyter_server
appsec-eval --target-repo jupyterhub
```
