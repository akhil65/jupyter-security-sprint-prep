import json
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

@dataclass
class Finding:
    tool: str
    category: str  # SAST, DAST, SCA, SECRETS, IAC, AI-SPM
    repo: str
    issue_id: str
    severity: str
    file_path: str
    line_number: int
    description: str
    raw_data: Dict[str, Any]


class StaticAnalysisParser:
    """Parses static analysis JSON outputs into actionable Finding objects."""

    def __init__(self, notes_dir: str = "notes", scans_dir: str = "scans"):
        self.notes_dir = Path(notes_dir)
        self.scans_dir = Path(scans_dir)

    def parse_bandit_json(self, repo_name: str) -> List[Finding]:
        """
        Parse bandit's machine-readable JSON output directly.
        This is more reliable than parsing the human-readable markdown summary.
        """
        findings = []
        json_file = self.scans_dir / "bandit" / f"{repo_name}.json"
        if not json_file.exists():
            logger.warning(f"Bandit JSON not found: {json_file}")
            return findings

        with open(json_file) as f:
            data = json.load(f)

        # Filter to HIGH and MEDIUM only — LOW is too noisy (mostly B101 assert_used)
        for result in data.get("results", []):
            severity = result.get("issue_severity", "LOW")
            if severity not in ("HIGH", "MEDIUM"):
                continue
            # Skip B101 (assert_used) — these are virtually always in test files
            if result.get("test_id") == "B101":
                continue

            findings.append(Finding(
                tool="bandit",
                category="SAST",
                repo=repo_name,
                issue_id=result.get("test_id", ""),
                severity=severity,
                file_path=result.get("filename", ""),
                line_number=result.get("line_number", 0),
                description=f"[{result.get('test_id')}] {result.get('test_name')}: {result.get('issue_text')}",
                raw_data=result,
            ))

        logger.info(f"Bandit: parsed {len(findings)} HIGH/MEDIUM findings for {repo_name}.")
        return findings

    def parse_semgrep_json(self, repo_name: str) -> List[Finding]:
        """
        Parse semgrep's combined JSON output directly.
        This replaces the fragile markdown line-scan approach.
        """
        findings = []
        json_file = self.scans_dir / "semgrep" / f"{repo_name}_combined.json"
        if not json_file.exists():
            logger.warning(f"Semgrep JSON not found: {json_file}")
            return findings

        with open(json_file) as f:
            data = json.load(f)

        # Skip placeholder files written before the real scan ran
        if data.get("_meta", {}).get("status") == "PENDING":
            logger.warning(f"Semgrep results for {repo_name} are still pending. Run scans/semgrep/run-semgrep.sh.")
            return findings

        for result in data.get("results", []):
            sev = result.get("extra", {}).get("severity", "WARNING")
            # Map semgrep severity labels to our standard labels
            severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
            severity = severity_map.get(sev, "MEDIUM")

            findings.append(Finding(
                tool="semgrep",
                category="SAST",
                repo=repo_name,
                issue_id=result.get("check_id", "").split(".")[-1],
                severity=severity,
                file_path=result.get("path", ""),
                line_number=result.get("start", {}).get("line", 0),
                description=result.get("extra", {}).get("message", ""),
                raw_data=result,
            ))

        logger.info(f"Semgrep: parsed {len(findings)} findings for {repo_name}.")
        return findings

    def collect_findings(self, target_repo: str) -> List[Finding]:
        logger.info(f"Running Static Analysis (SAST - Bandit/Semgrep) for {target_repo}...")
        findings = []
        findings.extend(self.parse_bandit_json(target_repo))
        findings.extend(self.parse_semgrep_json(target_repo))
        logger.info(f"Collected {len(findings)} actionable SAST findings.")
        return findings


class SCAIntegration:
    """
    Software Composition Analysis via pip-audit JSON output.

    NOTE: The stubs below return TRAINING PLAYGROUND examples only —
    they are clearly labelled and NOT injected into production repo evaluations.
    Real SCA results come from the pip-audit JSON files in scans/pip-audit/.
    """

    def run_sca(self, target_repo: str) -> List[Finding]:
        logger.info("Running SCA Analysis (pip-audit)...")

        # Read real pip-audit results if available
        findings = self._parse_pip_audit_json(target_repo)
        if findings is not None:
            return findings

        # No real results — return empty rather than misleading mock data
        logger.warning(
            "pip-audit JSON not found or still pending. "
            "Run scans/pip-audit/run-pip-audit.sh to generate real SCA results."
        )
        return []

    def _parse_pip_audit_json(self, repo_name: str):
        json_file = Path("scans") / "pip-audit" / f"{repo_name}.json"
        if not json_file.exists():
            return None

        with open(json_file) as f:
            data = json.load(f)

        # Placeholder file written before real scan — not real results
        if isinstance(data.get("dependencies", [{}])[0].get("vulns"), str):
            return None

        findings = []
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                findings.append(Finding(
                    tool="pip-audit",
                    category="SCA",
                    repo=repo_name,
                    issue_id=vuln.get("id", ""),
                    severity="HIGH",
                    file_path="pyproject.toml / requirements.txt",
                    line_number=0,
                    description=(
                        f"{dep.get('name')}=={dep.get('version')}: "
                        f"{vuln.get('description', '')} "
                        f"(fix: {vuln.get('fix_versions', [])})"
                    ),
                    raw_data={"dep": dep, "vuln": vuln},
                ))
        return findings


class SecretScannerIntegration:
    """
    Stub for Gitleaks / TruffleHog secret detection.

    TRAINING PLAYGROUND ONLY — the finding below is a demo example
    from training_playground/vulnerable_app.py. It is NOT a real finding
    from jupyter_server or jupyterhub.
    """

    TRAINING_EXAMPLE = Finding(
        tool="trufflehog",
        category="SECRETS",
        repo="training_playground",
        issue_id="exposed-aws-key-demo",
        severity="CRITICAL",
        file_path="training_playground/vulnerable_app.py",
        line_number=5,
        description=(
            "[TRAINING DEMO] Hardcoded AWS Access Key ID pattern detected. "
            "In production: run `gitleaks detect` or `trufflehog git` against the repo."
        ),
        raw_data={"demo": True, "active": False},
    )

    def run_secrets(self, target_repo: str) -> List[Finding]:
        logger.info("Running Secret Detection (Gitleaks/TruffleHog stub)...")
        if target_repo == "training_playground":
            return [self.TRAINING_EXAMPLE]
        # Real runs: invoke gitleaks/trufflehog CLI and parse output here
        logger.warning(
            "Secret scanner is a stub. Integrate gitleaks or trufflehog CLI for real results."
        )
        return []


class IaCScannerIntegration:
    """
    Stub for Trivy / Checkov IaC scanning.

    TRAINING PLAYGROUND ONLY — the finding below is a demo example
    from training_playground/main.tf. It is NOT a real finding
    from jupyter_server or jupyterhub infrastructure.
    """

    TRAINING_EXAMPLE = Finding(
        tool="trivy",
        category="IAC",
        repo="training_playground",
        issue_id="AVD-AWS-0057-demo",
        severity="HIGH",
        file_path="training_playground/main.tf",
        line_number=7,
        description=(
            "[TRAINING DEMO] S3 bucket uses deprecated 'acl = public-read'. "
            "In production: run `trivy config` or `checkov -d .` against your Terraform."
        ),
        raw_data={"demo": True, "framework": "Terraform"},
    )

    def run_iac(self, target_repo: str) -> List[Finding]:
        logger.info("Running IaC Misconfiguration Scan (Trivy/Checkov stub)...")
        if target_repo == "training_playground":
            return [self.TRAINING_EXAMPLE]
        logger.warning(
            "IaC scanner is a stub. Integrate trivy or checkov CLI for real results."
        )
        return []


class AISPMScanner:
    """
    Stub for AI Security Posture Management (nb-defense / notebook scanning).

    TRAINING PLAYGROUND ONLY — the finding below is a demo example.
    It is NOT a real finding from jupyter_server or jupyterhub.
    """

    TRAINING_EXAMPLE = Finding(
        tool="nb-defense",
        category="AI-SPM",
        repo="training_playground",
        issue_id="AI-PII-LEAK-demo",
        severity="MEDIUM",
        file_path="training_playground/notebooks/example.ipynb",
        line_number=3,
        description=(
            "[TRAINING DEMO] Unencrypted PII pattern in notebook cell outputs. "
            "In production: run `nbdefense scan` against your notebooks."
        ),
        raw_data={"demo": True, "cell_type": "code_output"},
    )

    def run_aispm(self, target_repo: str) -> List[Finding]:
        logger.info("Running AI-SPM checks for Jupyter Notebooks (stub)...")
        if target_repo == "training_playground":
            return [self.TRAINING_EXAMPLE]
        logger.warning(
            "AI-SPM scanner is a stub. Integrate nb-defense CLI for real results."
        )
        return []
