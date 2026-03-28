# AppSec Sprint Evaluator Dashboard: training_playground

> **Note:** This is a reference example showing what the dashboard looks like when
> `appsec-eval --target-repo training_playground` runs against the training playground files.
> Regenerate by running: `appsec-eval --target-repo training_playground`

## Overview

This report aggregates findings across SAST, SCA, Secrets, IaC, and AI-SPM for the
`training_playground` target. DAST is not applicable here (no live server to probe).

### Risk Breakdown
- **SAST:** 2 (bandit/semgrep against vulnerable_app.py)
- **SCA:** 1 (pip-audit against requirements.txt)
- **SECRETS:** 1 (stub demo — gitleaks/trufflehog not integrated)
- **IAC:** 1 (stub demo — trivy/checkov not integrated)
- **AI-SPM:** 1 (stub demo — nb-defense not integrated; example.ipynb provided for demonstration)

---

## Actionable True Positives (6)

### 1. [HIGH] SAST (bandit): B602
**Location:** `training_playground/vulnerable_app.py:16`

**Description:** subprocess.Popen with shell=True — command injection risk if user_input is attacker-controlled.

**AI Suggested Fix:**
```python
# Replace shell=True with a list of arguments:
subprocess.Popen(["echo", user_input])
```

---

### 2. [MEDIUM] SAST (bandit): B301
**Location:** `training_playground/vulnerable_app.py:21`

**Description:** pickle.loads() called on untrusted data — insecure deserialization vulnerability.

**AI Suggested Fix:**
```python
# Use json.loads() for trusted data, or hmac-signed payloads for untrusted input.
```

---

### 3. [HIGH] SCA (pip-audit): PYSEC-2023-74-demo
**Location:** `training_playground/requirements.txt:2`

**Description:** [TRAINING DEMO] requests==2.28.1 is pinned below the fix for CVE-2023-32681 (proxy auth header leak). Upgrade to >=2.31.0. urllib3<1.26.17 is also below the fix for CVE-2023-43804.

**AI Suggested Fix:**
```python
# In requirements.txt:
requests>=2.31.0
urllib3>=1.26.17
```

---

### 4. [CRITICAL] SECRETS (trufflehog): exposed-aws-key-demo
**Location:** `training_playground/vulnerable_app.py:11`

**Description:** [TRAINING DEMO] Hardcoded AWS Access Key ID pattern detected. In production: run `gitleaks detect` or `trufflehog git` against the repo.

**AI Suggested Fix:**
```python
# Never hardcode credentials. Use environment variables:
aws_secret = os.environ["AWS_SECRET_ACCESS_KEY"]
```

---

### 5. [HIGH] IAC (trivy): AVD-AWS-0057-demo
**Location:** `training_playground/main.tf:23`

**Description:** [TRAINING DEMO] S3 bucket 'insecure' has no public access block enabled. In production: run `trivy config` or `checkov -d .` against your Terraform.

**AI Suggested Fix:**
```hcl
# Add an aws_s3_bucket_public_access_block resource:
resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.insecure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

---

### 6. [MEDIUM] AI-SPM (nb-defense): AI-PII-LEAK-demo
**Location:** `training_playground/notebooks/example.ipynb:3`

**Description:** [TRAINING DEMO] Unencrypted PII pattern in notebook cell outputs. In production: run `nbdefense scan` against your notebooks.

**AI Suggested Fix:**
```python
# Strip outputs before committing notebooks:
jupyter nbconvert --clear-output --inplace notebook.ipynb
```

---
