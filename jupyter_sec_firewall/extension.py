import logging
from jupyter_server.extension.application import ExtensionApp
from .handlers import SecureZMQChannelsWebsocketConnection

logger = logging.getLogger("jupyter_sec_firewall")

class JupyterSecFirewall(ExtensionApp):
    name = "jupyter_sec_firewall"

    def initialize_handlers(self):
        # We don't need to add a colliding Tornado route.
        # We will override the connection class in initialize_settings instead,
        # or we can do it right here since serverapp is available.
        pass

    def initialize_settings(self):
        # Override the connection class in the web app settings
        self.serverapp.web_app.settings['kernel_websocket_connection_class'] = SecureZMQChannelsWebsocketConnection
        logger.info("Jupyter Security Firewall injected custom WebSocket connection class.")

def _jupyter_server_extension_points():
    return [{
        "module": "jupyter_sec_firewall.extension",
        "app": JupyterSecFirewall
    }]

# NOTE: load_jupyter_server_extension (legacy entry point) is intentionally
# absent. It is incompatible with ExtensionApp — calling
# extension.initialize(server_app) with a server_app argument would raise
# a TypeError. All loading is handled via _jupyter_server_extension_points()
# above, which is the correct modern mechanism.
