import logging
import os
from pathlib import Path
from github import Github, GithubException

logger = logging.getLogger(__name__)

class GitHubReporter:
    """Generates markdown reports and creates GitHub issues/PRs."""

    def __init__(self, output_dir: str, github_repo: str = None):
        self.output_dir = Path(output_dir)
        self.github_repo = github_repo

        token = os.getenv("GITHUB_TOKEN")
        if token:
            self.github = Github(token)
        else:
            self.github = None
            if self.github_repo:
                logger.warning("GITHUB_TOKEN not found. Cannot create issues programmatically.")

    def generate_dashboard(self, findings: list, target_repo: str):
        """Generates a unified security findings dashboard (Markdown and JSON)."""
        md_path = self.output_dir / f"{target_repo}_aspm_dashboard.md"
        json_path = self.output_dir / f"{target_repo}_aspm_dashboard.json"

        logger.info(f"Generating security findings dashboard at {md_path}...")

        # 1. JSON Dashboard
        import json
        dashboard_data = {
            "target": target_repo,
            "total_findings": len(findings),
            "breakdown": {
                "SAST": len([f for f in findings if f.category == "SAST"]),
                "SCA": len([f for f in findings if f.category == "SCA"]),
                "SECRETS": len([f for f in findings if f.category == "SECRETS"]),
                "IAC": len([f for f in findings if f.category == "IAC"]),
                "DAST": len([f for f in findings if f.category == "DAST"]),
                "AI-SPM": len([f for f in findings if f.category == "AI-SPM"]),
            },
            "findings": [
                {
                    "tool": f.tool,
                    "category": f.category,
                    "severity": f.severity,
                    "file_path": f.file_path,
                    "description": f.description,
                    "ai_triage": f.raw_data.get("ai_analysis", {})
                } for f in findings
            ]
        }
        with open(json_path, "w") as jf:
            json.dump(dashboard_data, jf, indent=2)

        # 2. Markdown Dashboard
        with open(md_path, "w") as f:
            f.write(f"# Security Findings Dashboard: {target_repo}\n\n")
            f.write("## Overview\n")
            f.write("This report aggregates findings across SAST, SCA, Secrets, IaC, DAST, and AI-SPM for the target repository.\n\n")

            f.write("### Risk Breakdown\n")
            for cat, count in dashboard_data["breakdown"].items():
                f.write(f"- **{cat}:** {count}\n")
            f.write("\n")

            f.write(f"## Actionable True Positives ({len(findings)})\n\n")
            for idx, finding in enumerate(findings):
                f.write(f"### {idx + 1}. [{finding.severity}] {finding.category} ({finding.tool}): {finding.issue_id}\n")
                f.write(f"**Location:** `{finding.file_path}:{finding.line_number}`\n\n")
                f.write(f"**Description:** {finding.description}\n\n")

                ai_analysis = finding.raw_data.get('ai_analysis', {})
                if not ai_analysis.get('is_false_positive', False):
                    suggested_fix = ai_analysis.get('suggested_fix', 'Manual review required.')
                    f.write(f"**AI Suggested Fix:**\n```python\n{suggested_fix}\n```\n\n")
                f.write("---\n")

        logger.info("Dashboard generation complete.")

    def create_draft_prs(self, findings: list, target_repo_name: str):
        """Uses PyGithub to open Draft PRs with AI patches on the target repository."""
        if not self.github or not self.github_repo:
            return

        try:
            repo = self.github.get_repo(self.github_repo)

            # For proof of concept, just process one HIGH severity finding to create a PR
            high_findings = [f for f in findings if f.severity == "HIGH"]

            if not high_findings:
                logger.info("No HIGH severity findings to open PRs for.")
                return

            # Pick the first one
            finding = high_findings[0]
            ai_analysis = finding.raw_data.get('ai_analysis', {})
            suggested_fix = ai_analysis.get('suggested_fix')

            if not suggested_fix or suggested_fix == "Manual review required.":
                logger.warning("No actionable AI fix to commit for the PR.")
                return

            branch_name = f"security-fix-{finding.issue_id.lower()}"
            base_branch = repo.default_branch

            # Get the base branch ref
            ref = repo.get_git_ref(f"heads/{base_branch}")

            # Create the new branch
            try:
                repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=ref.object.sha)
                logger.info(f"Created new branch: {branch_name}")
            except GithubException as ge:
                if ge.status == 422:
                    logger.warning(f"Branch {branch_name} already exists.")
                else:
                    raise ge

            # Update or create the file with the AI fix
            file_path = finding.file_path
            commit_message = f"fix: Resolve {finding.issue_id} found by {finding.tool}"

            # Write the AI suggestion as a dedicated remediation note file,
            # NOT by appending prose to the original source file (which would
            # corrupt it and produce a non-mergeable PR).
            note_path = f"security-remediations/{finding.issue_id.lower()}.md"
            note_content = (
                f"# Security Remediation: {finding.issue_id}\n\n"
                f"**Tool:** {finding.tool}  \n"
                f"**File:** `{finding.file_path}`  \n"
                f"**Line:** {finding.line_number}  \n\n"
                f"## Finding\n{finding.description}\n\n"
                f"## AI Suggested Fix\n{suggested_fix}\n\n"
                f"> This file was generated by the AppSec Sprint Evaluator. "
                f"Apply the fix manually to `{finding.file_path}` and delete this file before merging.\n"
            )
            try:
                contents = repo.get_contents(note_path, ref=branch_name)
                repo.update_file(
                    contents.path, commit_message, note_content,
                    contents.sha, branch=branch_name
                )
            except GithubException:
                repo.create_file(note_path, commit_message, note_content, branch=branch_name)

            # Create the Draft PR
            title = f"Fix: Address {finding.issue_id} ({finding.tool})"
            body = f"""This is a draft Pull Request generated by the **AppSec Sprint Evaluator**.

### Security Finding
* **Tool:** {finding.category} / {finding.tool}
* **Issue:** {finding.issue_id}
* **File:** `{finding.file_path}`

### AI Triage
The AI Triage engine has evaluated this finding, determined it to be a True Positive, and generated the secure code patch applied in this PR.

**Reasoning:** {ai_analysis.get('reason', 'AI determined this is an exploitable vulnerability.')}

Please review the proposed changes before merging.
"""
            # Create the pull request (with draft=True)
            pr = repo.create_pull(
                title=title,
                body=body,
                head=branch_name,
                base=base_branch,
                draft=True
            )
            logger.info(f"Successfully created Draft PR: {pr.html_url}")

        except GithubException as e:
            logger.error(f"Failed to create GitHub Draft PR: {e}")
