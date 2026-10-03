import os

DEFAULT_PORT = 8180
AUTO_REFRESH_SEC = 10
# Security-first default: only expose the dashboard on the local machine.
# Use --host explicitly if remote interface binding is intentionally required.
LISTEN_HOST = "127.0.0.1"
SERVER_VER = "1.0"
DEFAULT_LANG = "zh"
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")


# g3 profile: keep dashboard-owned state out of upstream OMP/Hermes directories.
DASHBOARD_STATE_DIR = os.path.abspath(os.path.expanduser(
    os.environ.get("SVC_DASHBOARD_STATE_DIR", "~/.local/state/svc-dashboard")
))
ENABLED_AGENTS = tuple(
    x.strip() for x in os.environ.get("SVC_DASHBOARD_AGENTS", "codex").split(",")
    if x.strip()
)
