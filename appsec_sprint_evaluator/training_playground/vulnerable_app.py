import os
import subprocess

# This is an intentionally vulnerable Python file for training purposes!

def connect_to_db():
    # Vulnerability 1: Hardcoded AWS-style Secret Key (Secret Detection / TruffleHog)
    # NOTE: "AKIAIOSFODNN7EXAMPLE" is Amazon's official docs example key and is
    # allowlisted by most modern secret scanners (TruffleHog, gitleaks). Use a
    # realistic-looking but clearly fake key to reliably trigger scanner alerts.
    aws_secret = "AKIA4HGEXAMPLEFAKE99"  # fake key format that triggers scanner heuristics
    print(f"Connecting to DB with {aws_secret}")

def execute_user_command(user_input):
    # Vulnerability 2: Command Injection / SAST (Bandit / Semgrep)
    subprocess.Popen(f"echo {user_input}", shell=True)

def insecure_deserialization(data):
    # Vulnerability 3: Insecure Pickle usage
    import pickle
    return pickle.loads(data)

if __name__ == "__main__":
    connect_to_db()
