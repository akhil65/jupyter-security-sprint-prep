import urllib.request
import json
import uuid
import websocket
import time
from threading import Thread

# Wait a bit for server to start
time.sleep(2)

base_url = "http://127.0.0.1:8888"
token = "testtoken"

# Create a kernel
req = urllib.request.Request(
    f"{base_url}/api/kernels",
    data=json.dumps({}).encode('utf-8'),
    headers={"Authorization": f"Token {token}", "Content-Type": "application/json"}
)
res = urllib.request.urlopen(req)
kernel_id = json.loads(res.read())['id']
print(f"Created kernel {kernel_id}")

ws_url = f"ws://127.0.0.1:8888/api/kernels/{kernel_id}/channels?token={token}"
ws = websocket.create_connection(ws_url)

def send_execute_request(code):
    msg_id = uuid.uuid4().hex
    msg = {
        "header": {
            "msg_id": msg_id,
            "username": "testuser",
            "session": uuid.uuid4().hex,
            "msg_type": "execute_request",
            "version": "5.3"
        },
        "parent_header": {},
        "metadata": {},
        "content": {
            "code": code,
            "silent": False,
            "store_history": False,
            "user_expressions": {},
            "allow_stdin": False
        },
        "channel": "shell"
    }
    ws.send(json.dumps(msg))
    return msg_id

def receive_replies(expected_replies=2):
    replies = []
    for _ in range(expected_replies):
        try:
            ws.settimeout(2.0)
            msg = json.loads(ws.recv())
            replies.append(msg)
        except websocket.WebSocketTimeoutException:
            break
    return replies

print("\n--- Testing Safe Code ---")
send_execute_request("print('hello')")
for r in receive_replies(10):
    if r['header']['msg_type'] == 'execute_reply':
        print(f"Safe code execution reply status: {r['content']['status']}")

print("\n--- Testing Malicious Code ---")
send_execute_request("import os")
replies_received = 0
for r in receive_replies(10):
    replies_received += 1
    if r['header']['msg_type'] == 'execute_reply':
        print(f"Malicious code execution reply status: {r['content']['status']}")
        print(f"Malicious code traceback: {r['content'].get('traceback', [])}")
    elif r['header']['msg_type'] == 'error':
        print(f"Malicious code error ename: {r['content']['ename']}")
        print(f"Malicious code traceback: {r['content'].get('traceback', [])}")
print(f"Replies received for malicious code: {replies_received}")

ws.close()
