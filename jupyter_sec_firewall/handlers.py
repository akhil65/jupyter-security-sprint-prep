import json
import logging
import uuid
import datetime
from typing import Any
from tornado import ioloop

from jupyter_server.services.kernels.connection.channels import ZMQChannelsWebsocketConnection
from jupyter_server.base.zmqhandlers import deserialize_binary_message
from jupyter_server.services.kernels.connection.base import deserialize_msg_from_ws_v1, serialize_msg_to_ws_v1

from .analyzer import analyze_code

logger = logging.getLogger("jupyter_sec_firewall")

class SecureZMQChannelsWebsocketConnection(ZMQChannelsWebsocketConnection):
    """
    A custom ZMQChannelsWebsocketConnection that intercepts execution requests and blocks them
    if they violate the security policy via AST analysis.
    """

    def handle_incoming_message(self, incoming_msg: Any) -> None:
        """
        Intercept incoming WebSocket messages from the browser before they go to ZMQ.
        """
        ws_msg = incoming_msg

        try:
            # Parse based on subprotocol (v1 multiplexed or legacy JSON)
            if self.subprotocol == "v1.kernel.websocket.jupyter.org":
                channel, msg_list = deserialize_msg_from_ws_v1(ws_msg)

                # session lives on the kernel manager, not directly on this connection.
                # Resolve it safely to avoid AttributeError.
                session = getattr(self, 'session', None) or getattr(
                    getattr(self, 'kernel_manager', None), 'session', None
                )
                if session is None:
                    # Cannot decode — pass through rather than drop silently.
                    super().handle_incoming_message(incoming_msg)
                    return

                idents, msg_list_rest = session.feed_identities(msg_list)
                msg = session.deserialize(msg_list_rest)
                msg_type = msg.get('header', {}).get('msg_type', '')
                content = msg.get('content', {})
            else:
                if isinstance(ws_msg, bytes):
                    msg = deserialize_binary_message(ws_msg)
                else:
                    msg = json.loads(ws_msg)

                channel = msg.get("channel", "")
                msg_type = msg.get("header", {}).get("msg_type", "")
                content = msg.get("content", {})

        except Exception as e:
            # Fail closed on malformed execution requests or unparseable messages.
            # We don't want to pass unknown payloads to the kernel.
            logger.error(f"Error intercepting message: {e}")
            # Do not pass the message to ZMQ.
            return

        if channel == "shell" and msg_type == "execute_request":
            code = content.get("code", "")

            # Run the AST security analyzer
            violations = analyze_code(code)

            if violations:
                logger.warning(f"Security Policy Violation in kernel {self.kernel_id}. Violations: {violations}")

                # Block execution and return an error mimicking the kernel
                self._send_error_reply(msg, violations)
                return

        # If no violation or not an execute_request, pass to the original connection handler
        super().handle_incoming_message(incoming_msg)

    def _send_error_reply(self, original_msg: dict, violations: list) -> None:
        """
        Send a fake error reply back to the client over the WebSocket
        so the notebook UI shows an error.
        """
        header = original_msg.get("header", {})
        session = header.get("session", "")
        version = header.get("version", "5.3")
        username = header.get("username", "username")

        def build_msg(msg_type, content, channel):
            now = datetime.datetime.utcnow().isoformat() + "Z"
            return {
                "channel": channel,
                "header": {
                    "msg_id": str(uuid.uuid4()),
                    "username": username,
                    "session": session,
                    "msg_type": msg_type,
                    "version": version,
                    "date": now
                },
                "parent_header": header,
                "metadata": {},
                "content": content
            }

        # 1. Send the execute_reply (status: error) on shell channel.
        # execution_count is REQUIRED by the Jupyter messaging protocol even for
        # error replies — without it JupyterLab leaves the cell counter as [*].
        reply_msg = build_msg("execute_reply", {
            "status": "error",
            "execution_count": None,
            "ename": "SecurityError",
            "evalue": "Security Policy Violation",
            "traceback": ["Security Policy Violation"] + [f"- {v}" for v in violations]
        }, "shell")

        # 2. Send execute_input on iopub so the frontend increments the cell counter.
        # This must arrive before the error message per the Jupyter protocol spec.
        code = original_msg.get("content", {}).get("code", "")
        execute_input_msg = build_msg("execute_input", {
            "code": code,
            "execution_count": None,
        }, "iopub")

        # 3. Send the error on iopub channel
        iopub_msg = build_msg("error", {
            "ename": "SecurityError",
            "evalue": "Security Policy Violation",
            "traceback": ["\x1b[31mSecurity Policy Violation Blocked Execution\x1b[0m"] + [f"\x1b[33m- {v}\x1b[0m" for v in violations]
        }, "iopub")

        # 4. Status messages
        status_busy = build_msg("status", {"execution_state": "busy"}, "iopub")
        status_idle = build_msg("status", {"execution_state": "idle"}, "iopub")

        def write(msg_dict):
            ch = msg_dict.get("channel", "iopub")
            if self.subprotocol == "v1.kernel.websocket.jupyter.org":
                # serialize_msg_to_ws_v1 expects a *list of packed bytes*, not a dict.
                # We must pack each field individually before passing to the serializer.
                session = getattr(self, 'session', None) or getattr(
                    getattr(self, 'kernel_manager', None), 'session', None
                )
                if session is None:
                    logger.error("Cannot send v1 error reply: session not available.")
                    return
                packed_list = [
                    session.pack(msg_dict["header"]),
                    session.pack(msg_dict["parent_header"]),
                    session.pack(msg_dict["metadata"]),
                    session.pack(msg_dict["content"]),
                ]
                bin_msg = serialize_msg_to_ws_v1(packed_list, ch)
                self.websocket_handler.write_message(bin_msg, binary=True)
            else:
                self.websocket_handler.write_message(json.dumps(msg_dict))

        def _send():
            try:
                write(status_busy)
                write(execute_input_msg)
                write(iopub_msg)
                write(reply_msg)
                write(status_idle)
            except Exception as e:
                logger.error(f"Failed to send security error reply: {e}")

        ioloop.IOLoop.current().add_callback(_send)
