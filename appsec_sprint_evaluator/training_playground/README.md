# Application Security Training Playground

Welcome to the **AppSec Sprint Evaluator Training Playground**.

This directory contains intentionally vulnerable files and configuration artifacts. It is designed to demonstrate how the Application Security Posture Management (ASPM) framework identifies, correlates, and triages vulnerabilities across multiple domains of the software supply chain.

## What's Inside?

- **`vulnerable_app.py`**: A Python script containing static application vulnerabilities (Command Injection, Insecure Deserialization via Bandit/Semgrep) and hardcoded secrets (AWS Keys via TruffleHog/Gitleaks).
- **`requirements.txt`**: A Python dependency file pinning outdated, vulnerable libraries (SCA via pip-audit/Syft/Grype).
- **`main.tf`**: A Terraform infrastructure-as-code template declaring a publicly readable AWS S3 bucket (IaC Scanning via Trivy/Checkov).

## How to use the Interactive Tutorial

To explore how the `appsec_sprint_evaluator` processes these vulnerabilities, categorizes them, filters them using AI, and generates Draft PRs, run the interactive guided tutorial from the root of the project:

```bash
appsec-tutorial
```

This will walk you step-by-step through the tool's architecture and demonstrate exactly how modern ASPM transforms chaotic scan noise into prioritized, actionable insights for maintainers.
