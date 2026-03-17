import logging
import requests
import time
import subprocess
import os
from .static_parser import Finding

logger = logging.getLogger(__name__)

class DynamicAnalysisModule:
    """Spins up a target app and runs a DAST probe."""

    def __init__(self, target_repo: str, port: int):
        self.target_repo = target_repo
        self.port = port
        self.findings = []
        self.process = None

    def start_target_app(self):
        """Attempts to spin up the target application (e.g. jupyter_server)."""
        logger.info(f"Attempting to start local instance of {self.target_repo} on port {self.port}...")

        # Simple heuristic to start a local server if it's installed
        env = os.environ.copy()

        try:
            # We run it in the background
            self.process = subprocess.Popen(
                ["jupyter", "server", f"--port={self.port}", "--no-browser", "--IdentityProvider.token=dasttoken"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env
            )
            time.sleep(3) # Wait for it to spin up

            # Verify it's up
            res = requests.get(f"http://127.0.0.1:{self.port}/api", headers={"Authorization": "Token dasttoken"}, timeout=5)
            if res.status_code == 200:
                logger.info(f"{self.target_repo} is running on port {self.port}.")
                return True
        except Exception as e:
            logger.warning(f"Failed to start target app locally: {e}")

        return False

    def run_dast_probe(self):
        """Simulates an OWASP ZAP API scan or basic fuzzer."""
        logger.info("Running DAST probe...")
        base_url = f"http://127.0.0.1:{self.port}"

        # Probe 1: Check for exposed API without token
        try:
            res = requests.get(f"{base_url}/api/kernels", timeout=3)
            if res.status_code == 200:
                self.findings.append(Finding(
                    tool="dast", repo=self.target_repo, issue_id="ZAP-1",
                    severity="HIGH", file_path="api/kernels", line_number=0,
                    description="Unauthenticated API access detected on /api/kernels",
                    raw_data={"status_code": res.status_code}
                ))
            else:
                logger.debug(f"API correctly enforces auth: {res.status_code}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"DAST probe failed: {e}")

        # Probe 2: Check security headers
        try:
            res = requests.get(base_url, timeout=3)
            missing_headers = []
            expected_headers = ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"]
            for h in expected_headers:
                if h not in res.headers:
                    missing_headers.append(h)

            if missing_headers:
                self.findings.append(Finding(
                    tool="dast", repo=self.target_repo, issue_id="ZAP-2",
                    severity="LOW", file_path="/", line_number=0,
                    description=f"Missing security headers: {', '.join(missing_headers)}",
                    raw_data={"headers": dict(res.headers)}
                ))
        except requests.exceptions.RequestException:
            pass

    def stop_target_app(self):
        if self.process:
            logger.info("Stopping local target app...")
            self.process.terminate()
            self.process.wait()

    def run_probe(self) -> list:
        if self.start_target_app():
            try:
                self.run_dast_probe()
            finally:
                self.stop_target_app()
        else:
            logger.warning("Skipping DAST probe because target app could not be started.")

        return self.findings
