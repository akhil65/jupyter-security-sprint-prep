"""
Integration test for jupyter_sec_firewall — legacy JSON WebSocket protocol.

Prerequisites:
  pip install websocket-client   # not in pyproject.toml yet — add it!
  jupyter server --IdentityProvider.token=testtoken --port=8888 &
  # Wait ~3s for the server to start, then run:
  python test_ws.py

NOTE: This test only exercises the legacy JSON protocol path.
The v1 multiplexed protocol (subprotocol="v1.kernel.websocket.jupyter.org")
used by modern JupyterLab clients is NOT covered here — add a separate
test using the v1 binary format to achieve full coverage.
"""

import sys
import urllib.request
import json
import uuid
import time

try:
    import websocket
except ImportError:
    sys.exit(
        "Missing dependency: pip install websocket-client\n"
        "Also add 'websocket-client' to jupyter_sec_firewall's pyproject.toml dependencies."
    )

BASE_URL = "http://127.0.0.1:8888"
TOKEN = "testtoken"


def create_kernel():
    req = urllib.request.Request(
        f"{BASE_URL}/api/kernels",
        data=json.dumps({}).encode("utf-8"),
        headers={
            "Authorization": f"Token {TOKEN}",
            "Content-Type": "application/json",
        },
    )
    res = urllib.request.urlopen(req)
    kernel_id = json.loads(res.read())["id"]
    print(f"Created kernel: {kernel_id}")
    return kernel_id


def send_execute_request(ws, code):
    msg = {
        "header": {
            "msg_id": uuid.uuid4().hex,
            "username": "testuser",
            "session": uuid.uuid4().hex,
            "msg_type": "execute_request",
            "version": "5.3",
        },
        "parent_header": {},
        "metadata": {},
        "content": {
            "code": code,
            "silent": False,
            "store_history": False,
            "user_expressions": {},
            "allow_stdin": False,
        },
        "channel": "shell",
    }
    ws.send(json.dumps(msg))


def collect_replies(ws, max_msgs=10, timeout=2.0):
    replies = []
    for _ in range(max_msgs):
        try:
            ws.settimeout(timeout)
            replies.append(json.loads(ws.recv()))
        except websocket.WebSocketTimeoutException:
            break
    return replies


def get_execute_reply(replies):
    for r in replies:
        if r["header"]["msg_type"] == "execute_reply":
            return r
    return None


def run_tests():
    kernel_id = create_kernel()
    ws_url = f"ws://127.0.0.1:8888/api/kernels/{kernel_id}/channels?token={TOKEN}"
    ws = websocket.create_connection(ws_url)

    failures = []

    # --- Test 1: Safe code should pass through and execute ---
    print("\n[TEST 1] Safe code: print('hello')")
    send_execute_request(ws, "print('hello')")
    reply = get_execute_reply(collect_replies(ws))
    assert reply is not None, "No execute_reply received for safe code"
    if reply["content"]["status"] != "ok":
        failures.append(f"TEST 1 FAILED: safe code was blocked — status={reply['content']['status']}")
    else:
        print("  PASS: safe code executed successfully")

    # --- Test 2: Restricted import should be blocked ---
    print("\n[TEST 2] Malicious code: import os")
    send_execute_request(ws, "import os")
    reply = get_execute_reply(collect_replies(ws))
    assert reply is not None, "No execute_reply received for malicious code"
    if reply["content"]["status"] != "error":
        failures.append(
            f"TEST 2 FAILED: 'import os' was NOT blocked — status={reply['content']['status']}"
        )
    else:
        ename = reply["content"].get("ename", "")
        assert ename == "SecurityError", f"Expected SecurityError, got {ename}"
        print(f"  PASS: 'import os' blocked with {ename}")

    # --- Test 3: open() should be allowed (legitimate file I/O) ---
    print("\n[TEST 3] Legitimate file I/O: open() call")
    send_execute_request(ws, "f = open.__class__.__name__")  # access the name, not a real open
    reply = get_execute_reply(collect_replies(ws))
    # open() itself (as a call) is restricted, but referencing the type name is not.
    # This is a canary: if this is blocked, visit_Name is still too aggressive.
    if reply and reply["content"]["status"] == "error":
        failures.append(
            "TEST 3 FAILED: legitimate name reference was incorrectly blocked by visit_Name"
        )
    else:
        print("  PASS: non-call name reference not over-blocked")

    # --- Test 4: eval() should be blocked ---
    print("\n[TEST 4] Dangerous builtin: eval('1+1')")
    send_execute_request(ws, "eval('1+1')")
    reply = get_execute_reply(collect_replies(ws))
    if reply and reply["content"]["status"] != "error":
        failures.append(f"TEST 4 FAILED: eval() was NOT blocked")
    else:
        print("  PASS: eval() blocked")

    ws.close()

    # --- Summary ---
    print("\n" + "="*50)
    if failures:
        print(f"FAILED — {len(failures)} test(s) failed:")
        for f in failures:
            print(f"  ✗ {f}")
        sys.exit(1)
    else:
        print("ALL TESTS PASSED")


if __name__ == "__main__":
    # Give the server a moment if this script is launched right after `jupyter server`
    time.sleep(2)
    run_tests()
