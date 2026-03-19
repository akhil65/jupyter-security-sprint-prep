import logging
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

@dataclass
class Finding:
    tool: str
    category: str # SAST, DAST, SCA, SECRETS, IAC, AI-SPM
    repo: str
    issue_id: str
    severity: str
    file_path: str
    line_number: int
    description: str
    raw_data: Dict[str, Any]

class StaticAnalysisParser:
    """Parses static analysis outputs into actionable objects."""

    def __init__(self, notes_dir: str = "notes", scans_dir: str = "scans"):
        self.notes_dir = Path(notes_dir)
        self.scans_dir = Path(scans_dir)

    def parse_bandit_notes(self, repo_name: str) -> List[Finding]:
        findings = []
        md_file = self.notes_dir / "bandit-findings.md"
        if not md_file.exists():
            return findings

        with open(md_file, "r") as f:
            lines = f.readlines()

        current_repo_section = None
        for line in lines:
            if line.startswith("### "):
                current_repo_section = line.strip().split()[-1]
                continue

            if current_repo_section == repo_name and "|" in line and "Test ID" not in line and "---" not in line:
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) >= 3:
                    test_id = parts[0]
                    location = parts[1]
                    issue = parts[2]

                    if ":" in location:
                        file_path, line_num_str = location.split(":", 1)
                        line_num = int(line_num_str.split(",")[0]) if line_num_str.replace(",", "").isdigit() else 0
                    else:
                        file_path, line_num = location, 0

                    findings.append(Finding(
                        tool="bandit",
                        category="SAST",
                        repo=repo_name,
                        issue_id=test_id,
                        severity="HIGH" if test_id in ["B701", "B602"] else "MEDIUM",
                        file_path=file_path,
                        line_number=line_num,
                        description=issue,
                        raw_data={"raw_line": line}
                    ))
        return findings

    def parse_semgrep_notes(self, repo_name: str) -> List[Finding]:
        findings = []
        md_file = self.notes_dir / "semgrep-findings.md"
        if not md_file.exists():
            return findings

        with open(md_file, "r") as f:
            lines = f.readlines()

        current_severity = "WARNING"
        for line in lines:
            if "High" in line and repo_name in line:
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) >= 4:
                    desc = parts[1]
                    loc = parts[3]

                    file_path = loc.split(":")[0]
                    line_num = 0
                    if ":" in loc:
                        line_parts = loc.split(":")[1].split(",")
                        if line_parts[0].isdigit():
                            line_num = int(line_parts[0])

                    findings.append(Finding(
                        tool="semgrep",
                        category="SAST",
                        repo=repo_name,
                        issue_id="semgrep-rule",
                        severity="HIGH",
                        file_path=file_path,
                        line_number=line_num,
                        description=desc,
                        raw_data={"raw_line": line}
                    ))
        return findings

    def collect_findings(self, target_repo: str) -> List[Finding]:
        logger.info(f"Running Static Analysis (SAST - Bandit/Semgrep) for {target_repo}...")
        findings = []
        findings.extend(self.parse_bandit_notes(target_repo))
        findings.extend(self.parse_semgrep_notes(target_repo))

        logger.info(f"Collected {len(findings)} actionable SAST findings.")
        return findings

class SCAIntegration:
    """Stubs for Software Composition Analysis (Syft/Grype/pip-audit)."""
    def run_sca(self, target_repo: str) -> List[Finding]:
        logger.info("Running SCA Analysis (Syft -> Grype)...")
        # Mocking finding for sprint eval
        return [
            Finding(
                tool="grype", category="SCA", repo=target_repo, issue_id="CVE-2023-32681",
                severity="HIGH", file_path="requirements.txt", line_number=4,
                description="Requests proxy auth header leak. Fixed in >=2.31.0",
                raw_data={"cve": "CVE-2023-32681", "package": "requests"}
            )
        ]

class SecretScannerIntegration:
    """Stubs for Gitleaks and TruffleHog."""
    def run_secrets(self, target_repo: str) -> List[Finding]:
        logger.info("Running Layered Secret Detection (Gitleaks -> TruffleHog)...")
        return [
            Finding(
                tool="trufflehog", category="SECRETS", repo=target_repo, issue_id="exposed-aws-key",
                severity="CRITICAL", file_path="config/settings.py", line_number=12,
                description="Active AWS Access Key ID found and verified via API ping.",
                raw_data={"active": True, "entropy": "high"}
            )
        ]

class IaCScannerIntegration:
    """Stubs for Trivy and Checkov."""
    def run_iac(self, target_repo: str) -> List[Finding]:
        logger.info("Running IaC Misconfiguration Scan (Trivy/Checkov)...")
        return [
            Finding(
                tool="trivy", category="IAC", repo=target_repo, issue_id="AVD-AWS-0057",
                severity="HIGH", file_path="deploy/terraform/main.tf", line_number=45,
                description="S3 bucket does not have public access block enabled.",
                raw_data={"framework": "Terraform"}
            )
        ]

class AISPMScanner:
    """Stubs for AI Security Posture Management (AI-SPM)."""
    def run_aispm(self, target_repo: str) -> List[Finding]:
        logger.info("Running AI-SPM checks for Jupyter Notebooks...")
        return [
            Finding(
                tool="nb-defense", category="AI-SPM", repo=target_repo, issue_id="AI-PII-LEAK",
                severity="MEDIUM", file_path="notebooks/training_data_prep.ipynb", line_number=3,
                description="Unencrypted PII detected in notebook cell outputs.",
                raw_data={"cell_type": "code_output"}
            )
        ]
