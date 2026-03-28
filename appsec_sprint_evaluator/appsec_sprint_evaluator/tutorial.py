import time
import sys
import os
from colorama import init, Fore, Style
from .static_parser import StaticAnalysisParser, SCAIntegration, SecretScannerIntegration, IaCScannerIntegration, AISPMScanner
from .ai_reviewer import AITriageEngine
from .github_reporter import GitHubReporter

init(autoreset=True)

def print_slow(text, delay=0.03):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def step_prompt():
    input(Fore.YELLOW + "\nPress [ENTER] to continue to the next step..." + Style.RESET_ALL)
    print("\n" + "="*60 + "\n")

def run_tutorial():
    os.system('clear' if os.name == 'posix' else 'cls')

    print_slow(Fore.CYAN + Style.BRIGHT + "============================================================")
    print_slow(Fore.CYAN + Style.BRIGHT + "   Welcome to the AppSec Sprint Evaluator Tutorial 🚀")
    print_slow(Fore.CYAN + Style.BRIGHT + "============================================================\n")

    print_slow("This interactive guide will walk you through evaluating the `training_playground`")
    print_slow("repository. We will simulate running multiple security scanners, aggregating")
    print_slow("the results into a unified findings dashboard, and triaging them with AI.")

    step_prompt()

    # 1. SAST
    print_slow(Fore.GREEN + "[Step 1] Static Application Security Testing (SAST)")
    print_slow("Scanning `training_playground/vulnerable_app.py` using Bandit...")
    time.sleep(1)
    sast = StaticAnalysisParser()
    findings_sast = sast.collect_findings("training_playground")
    for f in findings_sast:
        print(Fore.RED + f" ✗ Found: [{f.severity}] {f.issue_id} in {f.file_path}:{f.line_number}")
        print(Fore.WHITE + f"   {f.description}")

    step_prompt()

    # 2. SCA
    print_slow(Fore.GREEN + "[Step 2] Software Composition Analysis (SCA)")
    print_slow("Running pip-audit against `training_playground/requirements.txt` to check for CVEs...")
    time.sleep(1)
    sca = SCAIntegration()
    findings_sca = sca.run_sca("training_playground")
    for f in findings_sca:
        print(Fore.RED + f" ✗ Found: {f.issue_id} in {f.file_path} (Severity: {f.severity})")
        print(Fore.WHITE + f"   Description: {f.description}")

    step_prompt()

    # 3. Secrets
    print_slow(Fore.GREEN + "[Step 3] Secret Detection (stub demo)")
    print_slow("Secrets scanner is a stub — demonstrates the detection pattern using a known fake key.")
    print_slow("In production: run `gitleaks detect` or `trufflehog git` for real secret scanning.")
    time.sleep(1)
    sec = SecretScannerIntegration()
    findings_sec = sec.run_secrets("training_playground")
    for f in findings_sec:
        print(Fore.RED + f" ✗ Found: {f.issue_id} in {f.file_path}")
        print(Fore.WHITE + f"   Note: [TRAINING DEMO] Key is intentionally fake — real runs use gitleaks/trufflehog to verify liveness.")

    step_prompt()

    # 4. IaC
    print_slow(Fore.GREEN + "[Step 4] Infrastructure as Code (IaC) Scanning (stub demo)")
    print_slow("IaC scanner is a stub — demonstrates the pattern using a known-bad main.tf.")
    print_slow("In production: run `trivy config .` or `checkov -d .` against your Terraform.")
    time.sleep(1)
    iac = IaCScannerIntegration()
    findings_iac = iac.run_iac("training_playground")
    for f in findings_iac:
        print(Fore.RED + f" ✗ Found: {f.issue_id} - {f.description}")

    step_prompt()

    # 5. AI-SPM
    print_slow(Fore.GREEN + "[Step 5] AI Security Posture Management (AI-SPM, stub demo)")
    print_slow("AI-SPM scanner is a stub — demonstrates notebook PII/credential detection.")
    print_slow("In production: run `nbdefense scan` against your notebooks.")
    time.sleep(1)
    aispm = AISPMScanner()
    findings_aispm = aispm.run_aispm("training_playground")
    for f in findings_aispm:
        print(Fore.RED + f" ✗ Found: {f.issue_id} in {f.file_path}:{f.line_number}")
        print(Fore.WHITE + f"   {f.description}")

    step_prompt()

    # 6. AI Triage
    print_slow(Fore.MAGENTA + Style.BRIGHT + "[Step 6] AI-Assisted Triage and Remediation")
    print_slow("The raw scanners found multiple vulnerabilities. Some might be false positives.")
    print_slow("Sending context to the AI Triage Engine (Mock/Gemini) to evaluate...")

    findings = findings_sast + findings_sca + findings_sec + findings_iac + findings_aispm
    ai = AITriageEngine(use_mock=True)

    time.sleep(2)
    triaged = ai.triage_findings(findings)
    print(Fore.CYAN + f"\nAI Triage Complete. Filtered down to {len(triaged)} actionable True Positives.")
    print_slow("The AI has also generated secure code fixes for each True Positive.")

    step_prompt()

    # 7. GitHub Integration
    print_slow(Fore.GREEN + "[Step 7] Automated GitHub Contribution (Draft PRs)")
    print_slow("The final step is to orchestrate these fixes back to the maintainers.")
    print_slow("The tool generates a unified security findings dashboard (Markdown/JSON) and opens a Draft PR.")
    time.sleep(1)

    print(Fore.BLUE + "   -> Generating `output/training_playground_security_dashboard.md`...")
    print(Fore.BLUE + "   -> Generating `output/training_playground_security_dashboard.json`...")
    print(Fore.BLUE + "   -> (Simulated) Opened GitHub Draft PR: 'Fix: Address High-Severity Security Findings'")

    print_slow(Fore.CYAN + Style.BRIGHT + "\n============================================================")
    print_slow(Fore.CYAN + Style.BRIGHT + "   Tutorial Complete! 🎉")
    print_slow(Fore.CYAN + Style.BRIGHT + "============================================================\n")
    print_slow("You have successfully simulated an automated Application Security Sprint evaluation.")
    print_slow("To run this for real against a target repository, use:")
    print_slow(Fore.YELLOW + "   appsec-eval --target-repo <repo_name> --github-repo <user/repo>")

def main():
    try:
        run_tutorial()
    except KeyboardInterrupt:
        print("\nTutorial aborted.")
        sys.exit(0)

if __name__ == "__main__":
    main()
