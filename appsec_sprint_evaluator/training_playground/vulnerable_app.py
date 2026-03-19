import os
import subprocess

# This is an intentionally vulnerable Python file for training purposes!

def connect_to_db():
    # Vulnerability 1: Hardcoded AWS Secret Key (Secret Detection / TruffleHog)
    aws_secret = "AKIAIOSFODNN7EXAMPLE"
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
