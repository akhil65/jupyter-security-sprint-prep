# Security Findings Dashboard: training_playground

## Overview
This report aggregates findings across SAST, SCA, Secrets, IaC, DAST, and AI-SPM for the target repository.

### Risk Breakdown
- **SAST:** 2
- **SCA:** 1
- **SECRETS:** 1
- **IAC:** 1
- **DAST:** 0
- **AI-SPM:** 1

## Actionable True Positives (6)

### 1. [HIGH] SAST (bandit): B602
**Location:** `training_playground/vulnerable_app.py:16`

**Description:** [B602] subprocess_popen_with_shell_equals_true: subprocess call with shell=True identified, security issue.

**AI Suggested Fix:** Manual review required.

---
### 2. [MEDIUM] SAST (bandit): B301
**Location:** `training_playground/vulnerable_app.py:21`

**Description:** [B301] pickle: Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

**AI Suggested Fix:** Manual review required.

---
### 3. [HIGH] SCA (pip-audit): PYSEC-2023-74-demo
**Location:** `training_playground/requirements.txt:2`

**Description:** [TRAINING DEMO] requests==2.28.1 is pinned below the fix for CVE-2023-32681 (proxy auth header leak). Upgrade to >=2.31.0. urllib3<1.26.17 is also below the fix for CVE-2023-43804. In production: run pip-audit against real requirements files.

**AI Suggested Fix:** Manual review required.

---
### 4. [CRITICAL] SECRETS (trufflehog): exposed-aws-key-demo
**Location:** `training_playground/vulnerable_app.py:11`

**Description:** [TRAINING DEMO] Hardcoded AWS Access Key ID pattern detected (AKIA4HGEXAMPLEFAKE99 at line 11). In production: run `gitleaks detect` or `trufflehog git` against the repo.

**AI Suggested Fix:** Manual review required.

---
### 5. [HIGH] IAC (trivy): AVD-AWS-0057-demo
**Location:** `training_playground/main.tf:23`

**Description:** [TRAINING DEMO] S3 bucket 'insecure' has no public access block enabled. In production: run `trivy config` or `checkov -d .` against your Terraform.

**AI Suggested Fix:** Manual review required.

---
### 6. [MEDIUM] AI-SPM (nb-defense): AI-PII-LEAK-demo
**Location:** `training_playground/notebooks/example.ipynb:3`

**Description:** [TRAINING DEMO] Unencrypted PII pattern in notebook cell outputs. In production: run `nbdefense scan` against your notebooks.

**AI Suggested Fix:** Manual review required.

---
