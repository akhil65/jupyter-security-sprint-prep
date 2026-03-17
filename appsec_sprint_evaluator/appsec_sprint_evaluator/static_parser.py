import json
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

@dataclass
class Finding:
    tool: str
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
        # We will attempt to parse the markdown notes if raw JSON isn't available,
        # but realistically, building a parser that reads raw scan outputs is better.
        # Since the 'scans' folder might be empty or missing in the repo,
        # we can parse the markdown tables from notes/ for this prototype.
        self.notes_dir = Path(notes_dir)
        self.scans_dir = Path(scans_dir)

    def parse_bandit_notes(self, repo_name: str) -> List[Finding]:
        """A simple heuristic parser for notes/bandit-findings.md"""
        findings = []
        md_file = self.notes_dir / "bandit-findings.md"
        if not md_file.exists():
            logger.warning(f"No bandit findings note found at {md_file}")
            return findings

        with open(md_file, "r") as f:
            lines = f.readlines()

        # Parse markdown tables heuristically
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
        logger.info(f"Collecting static analysis findings for {target_repo}...")
        findings = []
        findings.extend(self.parse_bandit_notes(target_repo))
        findings.extend(self.parse_semgrep_notes(target_repo))

        logger.info(f"Collected {len(findings)} actionable static analysis findings for {target_repo}.")
        return findings
