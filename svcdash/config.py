import os

DEFAULT_PORT = 8180
AUTO_REFRESH_SEC = 10
# Security-first default: only expose the dashboard on the local machine.
# Use --host explicitly if remote interface binding is intentionally required.
LISTEN_HOST = "127.0.0.1"
SERVER_VER = "1.0"
DEFAULT_LANG = "zh"
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
