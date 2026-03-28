# Application Security Training Playground

Welcome to the **AppSec Sprint Evaluator Training Playground**.

This directory contains intentionally vulnerable files and configuration artifacts. It is designed to demonstrate how the Application Security Posture Management (ASPM) framework identifies, correlates, and triages vulnerabilities across multiple domains of the software supply chain.

## What's Inside?

- **`vulnerable_app.py`**: A Python script containing static application vulnerabilities (Command Injection, Insecure Deserialization via Bandit/Semgrep) and hardcoded secrets (AWS Keys via TruffleHog/Gitleaks).
- **`requirements.txt`**: A Python dependency file pinning outdated, vulnerable libraries (SCA via pip-audit/Syft/Grype).
- **`main.tf`**: A Terraform infrastructure-as-code template declaring a publicly readable AWS S3 bucket (IaC Scanning via Trivy/Checkov).

## External Vulnerable Environments

For deeper dynamic testing (DAST) and comprehensive platform evaluations, we recommend pointing the evaluator at the following open-source, intentionally vulnerable web applications:

1. **[TIWAP (Totally Insecure Web Application Project)](https://github.com/tombstoneghost/TIWAP)** — A deliberately vulnerable web app covering OWASP Top 10 categories including SQLi, XSS, CSRF, and command injection. Good for validating DAST scanner coverage breadth.
2. **[SasanLabs VulnerableApp](https://github.com/SasanLabs/VulnerableApp)** — A Spring Boot application with a wide range of intentional vulnerabilities, well-suited for API-level DAST testing.
3. **[OWASP WebGoat](https://github.com/WebGoat/WebGoat)** — The canonical OWASP learning application covering business logic flaws, authentication bypass, and API vulnerabilities in a realistic Java/Spring environment.

## How to use the Interactive Tutorial

To explore how the `appsec_sprint_evaluator` processes these vulnerabilities, categorizes them, filters them using AI, and generates Draft PRs, run the interactive guided tutorial from the root of the project:

```bash
appsec-tutorial
```

This will walk you step-by-step through the tool's architecture and demonstrate exactly how modern ASPM transforms chaotic scan noise into prioritized, actionable insights for maintainers.
