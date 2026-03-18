# Unified ASPM Dashboard: training_playground

## Overview
This report aggregates findings across SAST, DAST, SCA, Secrets, IaC, and AI-SPM into a unified risk matrix.

### Risk Breakdown
- **SAST:** 0
- **SCA:** 1
- **SECRETS:** 1
- **IAC:** 1
- **DAST:** 1
- **AI-SPM:** 1

## Actionable True Positives (5)

### 1. [HIGH] SCA (grype): CVE-2023-32681
**Location:** `requirements.txt:4`

**Description:** Requests proxy auth header leak. Fixed in >=2.31.0

**AI Suggested Fix:**
```python
Please review this manually.
```

---
### 2. [CRITICAL] SECRETS (trufflehog): exposed-aws-key
**Location:** `config/settings.py:12`

**Description:** Active AWS Access Key ID found and verified via API ping.

**AI Suggested Fix:**
```python
Please review this manually.
```

---
### 3. [HIGH] IAC (trivy): AVD-AWS-0057
**Location:** `deploy/terraform/main.tf:45`

**Description:** S3 bucket does not have public access block enabled.

**AI Suggested Fix:**
```python
Please review this manually.
```

---
### 4. [MEDIUM] AI-SPM (nb-defense): AI-PII-LEAK
**Location:** `notebooks/training_data_prep.ipynb:3`

**Description:** Unencrypted PII detected in notebook cell outputs.

**AI Suggested Fix:**
```python
Please review this manually.
```

---
### 5. [LOW] DAST (zap-dast): ZAP-2
**Location:** `/:0`

**Description:** Missing security headers: X-Frame-Options

**AI Suggested Fix:**
```python
Please review this manually.
```

---
