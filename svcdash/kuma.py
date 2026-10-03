"""Uptime Kuma summary integration for the private g3 dashboard.

Uses Kuma's Prometheus /metrics endpoint. Credentials are read only from
environment variables and are never returned to the browser.
"""
import base64
import os
import re
import time
import urllib.error
import urllib.request

KUMA_URL = os.environ.get("SVC_KUMA_URL", "http://127.0.0.1:3001").rstrip("/")
_CACHE = {"t": 0.0, "data": None}
_CACHE_SEC = 15

_LABEL_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)="((?:\\.|[^"])*)"')


def _decode_label(value):
    return value.replace(r"\n", "\n").replace(r'\"', '"').replace(r"\\", "\\")[:200]


def _parse_labels(blob):
    return {k: _decode_label(v) for k, v in _LABEL_RE.findall(blob or "")}


def parse_metrics(text):
    """Return one current status per monitor from Prometheus exposition text.

    Kuma may emit duplicate series for a monitor when labels/tags changed.
    Prefer an UP series if duplicates disagree to avoid stale-label false alarms.
    """
    monitors = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line.startswith("monitor_status{"):
            continue
        close = line.rfind("}")
        if close < 0:
            continue
        labels = _parse_labels(line[len("monitor_status{"):close])
        try:
            status = int(float(line[close + 1:].strip().split()[0]))
        except (ValueError, IndexError):
            continue
        mid = labels.get("monitor_id")
        key = mid or "|".join([
            labels.get("monitor_name", ""),
            labels.get("monitor_type", ""),
            labels.get("monitor_url", ""),
            labels.get("monitor_hostname", ""),
            labels.get("monitor_port", ""),
        ])
        if not key:
            continue
        item = {
            "id": mid or "",
            "name": labels.get("monitor_name") or "monitor",
            "type": labels.get("monitor_type") or "",
            "status": status,
        }
        old = monitors.get(key)
        if old is None or (old["status"] != 1 and status == 1):
            monitors[key] = item
    return list(monitors.values())


def _auth_header():
    key = os.environ.get("SVC_KUMA_API_KEY", "")
    if key:
        raw = ":" + key
    else:
        user = os.environ.get("SVC_KUMA_USER", "")
        password = os.environ.get("SVC_KUMA_PASSWORD", "")
        if not user and not password:
            return None
        raw = user + ":" + password
    return "Basic " + base64.b64encode(raw.encode("utf-8")).decode("ascii")


def _fetch_metrics():
    req = urllib.request.Request(
        KUMA_URL + "/metrics",
        headers={"Accept": "text/plain", "User-Agent": "G3-Hub/1.0"},
    )
    auth = _auth_header()
    if auth:
        req.add_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.read(2 * 1024 * 1024).decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return None, "auth_required"
        return None, "http_" + str(e.code)
    except (urllib.error.URLError, TimeoutError, OSError):
        return None, "unreachable"


def summary(force=False):
    now = time.time()
    if not force and _CACHE["data"] is not None and now - _CACHE["t"] < _CACHE_SEC:
        return _CACHE["data"]

    raw, err = _fetch_metrics()
    if err:
        data = {
            "ok": False,
            "source": "uptime-kuma",
            "error": err,
            "auth_required": err == "auth_required",
            "configured": bool(_auth_header()),
        }
        _CACHE.update(t=now, data=data)
        return data

    monitors = parse_metrics(raw)
    counts = {"up": 0, "down": 0, "pending": 0, "maintenance": 0, "unknown": 0}
    down_names = []
    pending_names = []
    for m in monitors:
        status = m["status"]
        if status == 1:
            counts["up"] += 1
        elif status == 0:
            counts["down"] += 1
            down_names.append(m["name"])
        elif status == 2:
            counts["pending"] += 1
            pending_names.append(m["name"])
        elif status == 3:
            counts["maintenance"] += 1
        else:
            counts["unknown"] += 1

    data = {
        "ok": True,
        "source": "uptime-kuma",
        "total": len(monitors),
        **counts,
        "down_monitors": sorted(set(down_names))[:12],
        "pending_monitors": sorted(set(pending_names))[:12],
        "updated": now,
    }
    _CACHE.update(t=now, data=data)
    return data
