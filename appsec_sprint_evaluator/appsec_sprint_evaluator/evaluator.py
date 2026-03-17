import logging
from .static_parser import StaticAnalysisParser
from .ai_reviewer import AITriageEngine
from .dast_probe import DynamicAnalysisModule
from .github_reporter import GitHubReporter

logger = logging.getLogger(__name__)

def run_evaluation(args):
    target_repo = args.target_repo
    logger.info(f"Starting AppSec Sprint Evaluation for: {target_repo}")

    # Step 1: Parse Static Findings
    parser = StaticAnalysisParser(notes_dir="notes", scans_dir="scans")
    findings = parser.collect_findings(target_repo)

    # Step 2: Dynamic Analysis
    dast = DynamicAnalysisModule(target_repo=target_repo, port=args.dast_port)
    dast_findings = dast.run_probe()
    findings.extend(dast_findings)

    # Step 3: AI-Assisted Triage
    ai_engine = AITriageEngine(use_mock=args.use_mock_ai)
    triaged_findings = ai_engine.triage_findings(findings)

    # Step 4: Generate Markdown templates & create GitHub Issues
    reporter = GitHubReporter(
        output_dir=args.output_dir,
        github_repo=args.github_repo
    )
    reporter.generate_report(triaged_findings, target_repo)
    if args.github_repo:
        reporter.create_draft_issues(triaged_findings)
    else:
        logger.info("Skipping GitHub Issue creation (no --github-repo provided).")

    logger.info("Evaluation complete. Please review the output directory.")
