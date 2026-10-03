"""Runtime identity/path helpers for portable deployments.

Defaults to the account running svc-dashboard. Root deployments can explicitly
set SVC_DASHBOARD_HOME and SVC_DASHBOARD_USER to point at the data owner.
"""
import os
import pwd

HOME = os.path.abspath(os.environ.get("SVC_DASHBOARD_HOME") or os.path.expanduser("~"))
try:
    _home_uid = os.stat(HOME).st_uid
except OSError:
    _home_uid = os.getuid()

USER = os.environ.get("SVC_DASHBOARD_USER") or pwd.getpwuid(_home_uid).pw_name
try:
    UID = pwd.getpwnam(USER).pw_uid
except KeyError:
    UID = os.getuid()


def user_command(argv):
    """Run argv as the dashboard data owner when the service itself is root."""
    argv = list(argv)
    if os.geteuid() == 0 and USER != "root":
        return ["sudo", "-n", "-u", USER] + argv
    return argv
