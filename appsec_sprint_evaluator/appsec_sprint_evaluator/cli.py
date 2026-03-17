import argparse
import logging
from pathlib import Path
import os
from .evaluator import run_evaluation

def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(levelname)s - %(message)s')

def main():
    parser = argparse.ArgumentParser(description="AppSec Sprint Evaluator for Project Jupyter")
    parser.add_argument(
        "--target-repo",
        type=str,
        default="jupyter_server",
        help="The target repository to evaluate (e.g. jupyter_server or a local path). Defaults to jupyter_server."
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="output",
        help="Directory to save generated Markdown reports and templates."
    )
    parser.add_argument(
        "--github-repo",
        type=str,
        help="The GitHub repository to open draft issues/PRs on (e.g., user/repo)."
    )
    parser.add_argument(
        "--dast-port",
        type=int,
        default=8888,
        help="Port to run the DAST probe against if launching a local instance."
    )
    parser.add_argument(
        "--use-mock-ai",
        action="store_true",
        help="Force the use of the Mock AI stub even if a Gemini API key is present."
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging."
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    # Ensure output dir exists
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)

    run_evaluation(args)

if __name__ == "__main__":
    main()
