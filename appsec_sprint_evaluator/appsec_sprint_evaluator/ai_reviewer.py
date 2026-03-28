import logging
import os
import json
from .static_parser import Finding
import google.generativeai as genai

logger = logging.getLogger(__name__)

class AITriageEngine:
    """Uses LLMs (Mock or Gemini) to filter false positives and suggest fixes."""

    def __init__(self, use_mock: bool = False):
        self.use_mock = use_mock
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.is_ready = False

        if not self.use_mock and self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-1.5-flash')
                self.is_ready = True
                logger.info("AI Triage: using Gemini (gemini-1.5-flash).")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini: {e}")
                self.use_mock = True
        else:
            self.use_mock = True

        if self.use_mock:
            logger.warning(
                "AI Triage is running in MOCK mode — results are heuristic stubs, not real LLM analysis. "
                "Set the GEMINI_API_KEY environment variable to enable real AI triage."
            )

    def _mock_triage(self, finding: Finding) -> dict:
        """Simulates an LLM response."""
        logger.debug(f"[MOCK] AI analyzing finding: {finding.issue_id} in {finding.file_path}")
        # Very simple heuristic mock logic
        if finding.tool == 'bandit' and 'assert_used' in finding.description:
            return {"is_false_positive": True, "reason": "Assertions in test files are expected."}
        elif finding.tool == 'semgrep' and 'template-unescaped-with-safe' in finding.description:
            return {"is_false_positive": False, "suggested_fix": "Remove the '| safe' filter in Jinja2 templates or validate input."}

        return {"is_false_positive": False, "suggested_fix": "Please review this manually."}

    def _gemini_triage(self, finding: Finding) -> dict:
        """Calls the actual Gemini API."""
        prompt = f"""
        You are an expert Application Security Engineer contributing to the Jupyter project.
        Review this static analysis finding and determine if it's a false positive.
        If it is a true positive, suggest a secure code fix.

        Tool: {finding.tool}
        Issue ID: {finding.issue_id}
        File: {finding.file_path}
        Line: {finding.line_number}
        Description: {finding.description}

        Respond ONLY with a JSON object in this format:
        {{"is_false_positive": boolean, "reason": "string", "suggested_fix": "string"}}
        """

        try:
            response = self.model.generate_content(prompt)
            # Try to parse the JSON response
            text = response.text.strip()
            if text.startswith("```json"):
                text = text.split("```json")[1].split("```")[0].strip()
            return json.loads(text)
        except Exception as e:
            logger.error(f"Gemini API call failed: {e}")
            return self._mock_triage(finding)

    def triage_findings(self, findings: list) -> list:
        logger.info(f"Starting AI-Assisted triage for {len(findings)} findings (Mock Mode: {self.use_mock})...")
        triaged = []

        for finding in findings:
            if self.use_mock:
                analysis = self._mock_triage(finding)
            else:
                analysis = self._gemini_triage(finding)

            finding.raw_data['ai_analysis'] = analysis

            # Filter out false positives
            if not analysis.get('is_false_positive', False):
                finding.raw_data['suggested_fix'] = analysis.get('suggested_fix', '')
                triaged.append(finding)

        logger.info(f"AI Triage completed. {len(triaged)} actionable true positives remaining.")
        return triaged
