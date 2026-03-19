import logging
from .static_parser import StaticAnalysisParser, SCAIntegration, SecretScannerIntegration, IaCScannerIntegration, AISPMScanner
from .ai_reviewer import AITriageEngine
from .dast_probe import DynamicAnalysisModule
from .github_reporter import GitHubReporter

logger = logging.getLogger(__name__)

def run_evaluation(args):
    target_repo = args.target_repo
    logger.info(f"--- Starting ASPM Evaluation Pipeline for: {target_repo} ---")

    findings = []

    # 1. Static Analysis (SAST)
    sast_parser = StaticAnalysisParser(notes_dir="notes", scans_dir="scans")
    findings.extend(sast_parser.collect_findings(target_repo))

    # 2. Software Composition Analysis (SCA)
    sca_module = SCAIntegration()
    findings.extend(sca_module.run_sca(target_repo))

    # 3. Secret Detection
    secrets_module = SecretScannerIntegration()
    findings.extend(secrets_module.run_secrets(target_repo))

    # 4. Infrastructure as Code (IaC) Scanning
    iac_module = IaCScannerIntegration()
    findings.extend(iac_module.run_iac(target_repo))

    # 5. AI Security Posture Management (AI-SPM)
    aispm_module = AISPMScanner()
    findings.extend(aispm_module.run_aispm(target_repo))

    # 6. Dynamic Analysis (DAST)
    dast = DynamicAnalysisModule(target_repo=target_repo, port=args.dast_port)
    findings.extend(dast.run_probe())

    # 7. AI-Assisted Triage (Filter FPs, suggest fixes)
    ai_engine = AITriageEngine(use_mock=args.use_mock_ai)
    triaged_findings = ai_engine.triage_findings(findings)

    # 8. Generate Unified ASPM Dashboard & PRs
    reporter = GitHubReporter(
        output_dir=args.output_dir,
        github_repo=args.github_repo
    )

    # Create the unified Markdown/JSON dashboard
    reporter.generate_dashboard(triaged_findings, target_repo)

    if args.github_repo:
        # Now automatically draft PRs with AI patches instead of just issues
        reporter.create_draft_prs(triaged_findings, target_repo)
    else:
        logger.info("Skipping GitHub API Integration (no --github-repo provided).")

    logger.info("ASPM Evaluation complete. Please review the output directory.")
