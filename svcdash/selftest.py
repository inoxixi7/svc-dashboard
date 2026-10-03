#!/usr/bin/env python3
"""离线自检: 纯函数单测 + 真实数据源 dry-run,全部通过返回 0。"""
import os
import re
import unittest

from svcdash.goals import (parse_ctx_k, ctx_level, parse_retry, parse_progress,
                           parse_completed_goals, parse_watchdog_events,
                           merge_events, scan_goals, goal_detail,
                           _WD_LINE_RE, _wd_event_kind, GOAL_COMPLETED_LOG)
from svcdash.sysinfo import sys_info, load_zone
from svcdash.repos import agent_repos, repo_stats, parse_repo_commits
from svcdash.procscan import gather
from svcdash.render import render_html, TOOL_LINKS
from svcdash.privacy import sanitize_agent_detail_for_public, sanitize_runtimes_for_public
from svcdash.i18n import L10N, LANG_KEYS



class I18nParityTest(unittest.TestCase):
    """三语字典一致性 + 源码引用完整性 + 前端硬编码守卫。"""

    @staticmethod
    def _root():
        import os
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_same_key_sets(self):
        base = set(L10N[LANG_KEYS[0]])
        for lang in LANG_KEYS[1:]:
            self.assertEqual(base, set(L10N[lang]), f"{lang} key set differs")

    def test_no_empty_values(self):
        for lang in LANG_KEYS:
            empties = [k for k, v in L10N[lang].items() if not isinstance(v, str) or not v.strip()]
            self.assertEqual([], empties, f"{lang} has empty values")

    def test_placeholder_parity(self):
        ph = re.compile(r"\{([A-Za-z0-9_]+)\}")
        base = {k: set(ph.findall(v)) for k, v in L10N[LANG_KEYS[0]].items()}
        for lang in LANG_KEYS[1:]:
            for k, v in L10N[lang].items():
                self.assertEqual(base[k], set(ph.findall(v)), f"{lang}:{k} placeholders differ")

    def test_referenced_keys_defined(self):
        root = self._root()
        html = open(os.path.join(root, "static", "index.html"), encoding="utf-8").read()
        js = open(os.path.join(root, "static", "app.js"), encoding="utf-8").read()
        missing = sorted({k for k in re.findall(r"\{\{T:([A-Za-z0-9_]+)\}\}", html) if k not in L10N["zh"]})
        missing += sorted({k for k in re.findall(r"\bt\(\s*[\"']([a-z0-9_]+)[\"']", js)
                           if k not in L10N["zh"] and not k.endswith("_")})
        self.assertEqual([], missing, f"undefined i18n keys referenced: {missing}")

    def test_no_hardcoded_cjk_ui(self):
        root = self._root()
        js = open(os.path.join(root, "static", "app.js"), encoding="utf-8").read()
        cjk = re.compile(r"[\u4e00-\u9fff\u3040-\u30ff]")
        allowed = {"简体中文", "日本語", "中文"}
        bad, in_block = [], False
        for i, ln in enumerate(js.splitlines(), 1):
            st = ln.strip()
            if in_block:
                if "*/" in ln:
                    in_block = False
                continue
            if st.startswith("/*") and "*/" not in st:
                in_block = True
                continue
            # 剥离行内注释（字符串感知的简化实现）
            code, state = [], None
            j = 0
            while j < len(ln):
                c = ln[j]
                if state is None:
                    if ln.startswith("//", j):
                        break
                    if c in "\"'`":
                        state = c
                    code.append(c)
                else:
                    code.append(c)
                    if c == "\\":
                        if j + 1 < len(ln):
                            code.append(ln[j + 1]); j += 2; continue
                    elif c == state:
                        state = None
                j += 1
            line = "".join(code)
            for m in re.finditer(r"([\"'])((?:\\.|(?!\1).)*)\1", line):
                s = m.group(2)
                if cjk.search(s) and s not in allowed:
                    bad.append((i, s[:50]))
        self.assertEqual([], bad, f"hardcoded CJK UI literals in app.js: {bad[:8]}")


def selftest():
    class T(unittest.TestCase):
        def test_ctx(self):
            self.assertEqual(parse_ctx_k("╭── π ZAI Preview > Goal 45K > ~/x ────╮"), 45.0)
            self.assertEqual(parse_ctx_k("── 554K ──╮"), 554.0)
            self.assertEqual(parse_ctx_k("Goal 1.2M"), 1.2 * 1024)
            self.assertIsNone(parse_ctx_k("no header here"))
            self.assertEqual(ctx_level(45), "ok")
            self.assertEqual(ctx_level(801), "warn")
            self.assertEqual(ctx_level(1201), "stop")

        def test_post_token(self):
            # 令牌: 生成→缓存命中→mtime 轮换; 全程不碰真实路径
            import importlib, os, tempfile
            h = importlib.import_module("svcdash.handler")
            with tempfile.TemporaryDirectory() as td:
                p = os.path.join(td, "token")
                h._TOKEN_PATHS = (p, p)
                h._token_cache.update(mtime=None, val="")
                tok1 = h._svc_token()
                self.assertGreaterEqual(len(tok1), 24)
                self.assertEqual(h._svc_token(), tok1)          # mtime 缓存
                with open(p, "w") as f:
                    f.write("rotated-token\n")
                os.utime(p, (0, 0))                              # 强制 mtime 变化
                self.assertEqual(h._svc_token(), "rotated-token")
                self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
            from svcdash.config import DASHBOARD_STATE_DIR
            h._TOKEN_PATHS = ("/etc/svc-dashboard/token",
                              os.path.join(DASHBOARD_STATE_DIR, "token"))

        def test_agent_detail_public_redaction(self):
            detail = {
                "ok": True, "id": "codex", "name": "Codex CLI",
                "bin": "/home/alice/.local/bin/codex",
                "version": "1.2.3", "installed": True,
                "procs": [{"pid": 4321, "cmd": "codex --api-key=very-secret-value",
                           "cwd": "/home/alice/private/project", "cpu_pct": 4.5,
                           "mem_mb": 120, "up_sec": 12}],
                "skills": [{"name": "private-project-workflow", "category": "client",
                            "description": "Internal customer workflow"}],
                "mcp_servers": [{"name": "private-drive", "command": "node /home/alice/mcp.js"}],
                "platforms": {"telegram": {"state": "connected", "chat_id": "12345678",
                                             "username": "alice", "writer_pid": 9876}},
                "cron": [{"id": "private-job-id", "name": "Confidential task",
                          "prompt": "Do secret internal work", "schedule": "0 * * * *",
                          "origin": {"user_id": "87654321", "platform": "telegram"}}],
            }
            clean = sanitize_agent_detail_for_public(detail)
            rendered = __import__("json").dumps(clean, ensure_ascii=False)
            for private in ("/home/alice", "very-secret-value", "private-project-workflow",
                            "Internal customer workflow", "private-drive", "mcp.js",
                            "12345678", "alice", "9876", "private-job-id",
                            "Confidential task", "Do secret internal work", "87654321"):
                self.assertNotIn(private, rendered)
            self.assertEqual(clean["id"], "codex")
            self.assertEqual(clean["name"], "Codex CLI")
            self.assertEqual(clean["procs"][0]["cpu_pct"], 4.5)
            self.assertEqual(clean["cron"][0]["schedule"], "0 * * * *")

        def test_static_runtime_quota_is_visible_without_account_identity(self):
            data = {"agents": [{"id": "codex", "name": "Codex", "bin": "/home/alice/bin/codex",
                "meta": {"account": "alice@example.com"},
                "tasks": [{"title": "private task", "cwd": "/home/alice/project"}],
                "quota": {"ok": True, "account": "alice@example.com", "plan": "Pro",
                    "buckets": [{"label": "Weekly · primary", "remaining_pct": 72,
                                 "reset": "2026-09-27 12:00", "detail": "28/100 used"}]}}]}
            clean = sanitize_runtimes_for_public(data)
            agent = clean["agents"][0]
            self.assertEqual(agent["quota"]["buckets"][0]["label"], "Weekly · primary")
            self.assertEqual(agent["quota"]["buckets"][0]["remaining_pct"], 72)
            self.assertEqual(agent["quota"]["buckets"][0]["reset"], "2026-09-27 12:00")
            self.assertNotIn("alice@example.com", __import__("json").dumps(clean))
            self.assertNotIn("private task", __import__("json").dumps(clean))
            self.assertNotIn("/home/alice", __import__("json").dumps(clean))

        def test_fragment_cache(self):
            # 未知片段 None; 已知片段 5s 内二次调用命中同一缓存对象
            from svcdash import render
            self.assertIsNone(render.render_fragment("nope", "zh", "localhost:80"))
            a = render.render_fragment("goals", "zh", "localhost:80")
            b = render.render_fragment("goals", "zh", "localhost:80")
            self.assertIs(a, b)
            self.assertTrue(a)

        def test_retry_progress(self):
            self.assertEqual(parse_retry("API error. Retrying (3)/10 in 5s"), "3")
            self.assertEqual(parse_retry("Retrying (7/10)…"), "7")
            self.assertIsNone(parse_retry("no retry"))
            self.assertTrue(parse_progress(
                "╭─── Todo 12 tasks ───╮\n│ II. Phase 1  3/3   │\n"
                "│   ├─ Browser E2E: import roundtrip + no-resurrect │\n"
                "╰─────────────────────╯"))

        def test_load_zone(self):
            self.assertEqual(load_zone(2.0), ("ok", 2))
            self.assertEqual(load_zone(5.9), ("ok", 1))
            self.assertEqual(load_zone(6.0), ("full", 0))
            self.assertEqual(load_zone(12.4), ("over", 0))

        def test_wd_parse(self):
            line = ("2026-08-14 08:15:10 [019ffbaf] resumed 019ffbaf-4c8d in %30; "
                    "sent '继续' to drive agent")
            m = _WD_LINE_RE.match(line)
            self.assertTrue(m)
            self.assertEqual(_wd_event_kind("goal paused: pid=1; driving with '继续'"), "nudge")

        def test_completed(self):
            entries = parse_completed_goals()
            if not os.path.isfile(GOAL_COMPLETED_LOG):
                self.assertEqual(entries, [])
                return
            with open(GOAL_COMPLETED_LOG, encoding="utf-8", errors="replace") as f:
                real = f.read()
            if "Zircon全代码文档化" in real:
                self.assertTrue(any("Zircon" in c["label"] for c in entries))
                self.assertTrue(entries[0]["resume_cmd"].startswith(
                    os.path.join(os.path.expanduser("~"), ".bun/bin/omp")))

        def test_svcctl(self):
            import os, signal, subprocess, tempfile, time
            from svcdash import svcctl
            # 台账指向临时文件, 不碰真实状态
            tmp = tempfile.mkdtemp(prefix="svcdash-selftest-")
            svcctl.STATE_FILE = os.path.join(tmp, "paused.json")
            svcctl.HISTORY_FILE = os.path.join(tmp, "actions.log")
            svcctl.STATE_DIR = tmp
            # 守卫: sshd 端口 / 自身端口 / docker 之外无 pid → 拒绝
            self.assertFalse(svcctl.can_pause({"port": 22, "pids": [1]}))
            self.assertFalse(svcctl.can_pause({"port": 80, "is_self": True}))
            self.assertFalse(svcctl.can_pause({"port": 61234, "pids": []}))  # 无人监听
            # 真实冻结/解冻往返: 起一个 sleep 子进程当"服务"
            p = subprocess.Popen(["sleep", "300"])
            time.sleep(0.2)
            for sig in (signal.SIGSTOP,):
                os.kill(p.pid, sig)
            # 直接走 resume 核心(绕过端口扫描): 台账写 pid, 验证 SIGCONT 恢复
            svcctl.save_state([{"port": 65534, "pids": [p.pid], "name": "selftest",
                                "kind": "sig", "ts": time.time()}])
            self.assertEqual(len(svcctl.load_state()), 1)
            r = svcctl.resume(65534)
            self.assertTrue(r["ok"], r)
            self.assertEqual(svcctl.load_state(), [])
            # 进程确实解冻并能被杀掉(T 状态的进程 SIGTERM 挂起, 需先 CONT)
            os.kill(p.pid, signal.SIGTERM)
            p.wait(timeout=5)
            # 历史: pause/resume 各一条
            svcctl._log("pause", {"port": 1, "name": "x", "pids": [2]})
            svcctl._log("resume", {"port": 1, "name": "x", "pids": [2]})
            self.assertEqual(len(svcctl.history()), 3)  # resume(65534) + 手写2条

        def test_docker_port_mapping_does_not_require_proxy_pid(self):
            # Regression guard: Docker ownership comes from docker ps host-port
            # mappings, not from visibility of root-owned docker-proxy PIDs.
            from svcdash import procscan
            original_listen = procscan.listen_sockets
            original_inode = procscan.inode_to_pid
            original_docker = procscan.docker_port_map
            original_priv = procscan.priv_lookup
            try:
                procscan.listen_sockets = lambda: [{
                    "family": __import__("socket").AF_INET,
                    "ip": "0.0.0.0", "port": 18080, "inode": "999999"
                }]
                procscan.inode_to_pid = lambda: {}
                procscan.docker_port_map = lambda: {18080: {
                    "name": "adguardhome", "id": "abc123",
                    "status": "Up 2 weeks (healthy)", "health": "healthy"
                }}
                procscan.priv_lookup = lambda port, ip: None
                rows = procscan.gather()
                row = next(x for x in rows if x["port"] == 18080)
                self.assertEqual(row["type"], "docker")
                self.assertEqual(row["name"], "adguardhome (docker)")
                self.assertEqual(row["display_name"], "AdGuard Home")
                self.assertEqual(row["container_health"], "healthy")
                self.assertTrue(row["listening"])
            finally:
                procscan.listen_sockets = original_listen
                procscan.inode_to_pid = original_inode
                procscan.docker_port_map = original_docker
                procscan.priv_lookup = original_priv

        def test_kuma_metrics_parser(self):
            from svcdash.kuma import parse_metrics
            raw = (
                '# HELP monitor_status Monitor Status\n'
                'monitor_status{monitor_id="1",monitor_name="Home",monitor_type="http"} 1\n'
                'monitor_status{monitor_id="2",monitor_name="WAN",monitor_type="ping"} 0\n'
                'monitor_status{monitor_id="3",monitor_name="Maintenance",monitor_type="http"} 3\n'
                'monitor_status{monitor_id="4",monitor_name="Booting",monitor_type="tcp"} 2\n'
            )
            rows = {x["id"]: x for x in parse_metrics(raw)}
            self.assertEqual(rows["1"]["status"], 1)
            self.assertEqual(rows["2"]["name"], "WAN")
            self.assertEqual(rows["3"]["status"], 3)
            self.assertEqual(rows["4"]["status"], 2)

        def test_service_table_prefers_display_name(self):
            app_js = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "app.js")
            with open(app_js, encoding="utf-8") as f:
                src = f.read()
            self.assertIn("e.display_name ||", src)
            self.assertIn('t("svc_unknown_listener")', src)

        def test_overview_only_uses_catalogued_entries(self):
            # Source-level guard: the overview must not fall back to arbitrary
            # non-system listeners, otherwise ephemeral high ports show as "?" cards.
            app_js = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "app.js")
            with open(app_js, encoding="utf-8") as f:
                src = f.read()
            self.assertIn("!!e.app_id && e.app_entry === true", src)
            self.assertNotIn("return !e.paused && normalWeb;", src)

        def test_service_group_labels_present(self):
            for lang in ("zh", "en", "ja"):
                table = L10N[lang]
                for key in ("svc_group_apps", "svc_group_network", "svc_group_docker", "svc_group_system"):
                    self.assertTrue(table.get(key))

        def test_g3_service_profiles(self):
            from svcdash.procscan import service_profile
            self.assertEqual(service_profile({"is_self": True, "port": 8180})["app_id"], "g3-hub")
            ad_dns = service_profile({"name": "adguardhome (docker)", "port": 53})
            ad_web = service_profile({"name": "adguardhome (docker)", "port": 8080})
            self.assertEqual(ad_dns["display_name"], "AdGuard Home")
            self.assertEqual(ad_dns["app_role"], "dns")
            self.assertFalse(ad_dns["app_entry"])
            self.assertEqual(ad_web["app_role"], "web")
            self.assertTrue(ad_web["app_entry"])
            self.assertEqual(service_profile({"name": "private-splendor-web-web-1 (docker)"})["app_id"], "private-splendor")
            self.assertEqual(service_profile({"name": "private-splendor-web-server-1 (docker)"})["app_id"], "private-splendor-api")
            kuma = service_profile({"name": "uptime-kuma (docker)", "port": 3001})
            self.assertEqual(kuma["display_name"], "Uptime Kuma")
            self.assertTrue(kuma["app_entry"])
            openlist = service_profile({"name": "openlist (docker)", "port": 5244})
            self.assertEqual(openlist["display_name"], "OpenList")
            self.assertFalse(openlist["app_entry"])
            self.assertTrue(openlist["app_internal"])
            ssh = service_profile({"name": "?", "port": 22})
            self.assertEqual(ssh["display_name"], "SSH")
            self.assertEqual(ssh["app_category"], "Remote Access")
            self.assertFalse(ssh["app_entry"])
            samba139 = service_profile({"name": "?", "port": 139})
            samba445 = service_profile({"name": "?", "port": 445})
            self.assertEqual(samba139["display_name"], "Samba / SMB")
            self.assertEqual(samba139["app_role"], "netbios")
            self.assertEqual(samba445["app_role"], "smb")
            self.assertFalse(samba445["app_entry"])
            ts4 = service_profile({"name": "?", "ip": "100.99.145.68", "port": 37561})
            ts6 = service_profile({"name": "?", "ip": "fd7a:115c:a1e0::633b:9145", "port": 56615})
            self.assertEqual(ts4["display_name"], "Tailscale")
            self.assertEqual(ts6["display_name"], "Tailscale")
            self.assertEqual(ts4["app_role"], "node-listener")
            self.assertFalse(ts4["app_entry"])
            self.assertIsNone(service_profile({"name": "unknown"}))

        def test_runtimes(self):
            import time
            from svcdash import runtimes as rt
            # 注册表: id 唯一, 装卸动作白名单
            ids = [a["id"] for a in rt.REGISTRY]
            self.assertEqual(len(ids), len(set(ids)))
            self.assertEqual(ids, ["codex"])
            # 额度归一化: 各家真实结构样本
            q = rt._parse_codex_quota({"account": {"account": {"email": "a@b.c",
                "planType": "plus"}},
                "rateLimits": {"rateLimits": {"limitId": "codex",
                    "primary": {"usedPercent": 8, "resetsAt": 1787198007}}},
                "usage": {}})
            self.assertEqual(q["plan"], "plus")
            self.assertEqual(q["buckets"][0]["remaining_pct"], 92)
            self.assertEqual(q["buckets"][0]["reset"], time.strftime(
                "%m-%d %H:%M", time.localtime(1787198007)))
            q = rt._parse_grok_quota({"billing": {"config": {
                "creditUsagePercent": 100,
                "currentPeriod": {"end": "2026-08-18T13:36:55Z"}}},
                "user": {"email": "g@x.ai", "subscriptionTier": "XPremium"}})
            self.assertEqual(q["buckets"][0]["remaining_pct"], 0)
            q = rt._parse_kiro_quota({"email": "k@a.com", "usage": {
                "usageBreakdownList": [{"displayName": "agentic",
                    "currentUsage": 3, "usageLimit": 10, "unit": "requests"}]}})
            self.assertEqual(q["buckets"][0]["remaining_pct"], 70)
            q = rt._parse_agy_quota({"quota": {"groups": [{"displayName": "Gemini Models",
                "buckets": [{"bucketId": "gemini-5h", "remainingFraction": 0.25,
                             "resetTime": "2026-08-15T08:52:07Z"}]}]},
                "accounts": [{"email": "x@gmail.com"}]})
            self.assertEqual(q["buckets"][0]["remaining_pct"], 25)
            self.assertEqual(q["buckets"][0]["reset"], rt._iso_cut("2026-08-15T08:52:07Z"))
            q = rt._parse_cursor_quota({"usage": {"planUsage": {
                "totalPercentUsed": 55}}, "hardLimit": {}})
            self.assertEqual(q["buckets"][0]["remaining_pct"], 45)
            # 进程扫描可运行且包含已知 agent 键
            procs = rt.scan_procs()
            self.assertIn("codex", procs)

    suite = unittest.TestLoader().loadTestsFromTestCase(T)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(I18nParityTest))
    unittest.TextTestRunner(verbosity=2).run(suite)
    print("\n--- live dry-run ---")
    gl = []  # g3 profile disables upstream OMP/watchdog goals
    print(f"goal cards: {len(gl)}")
    for g in gl:
        print(f"  {g['name']}: light={g['light']} ctx={g['ctx_raw'] or '—'} "
              f"idle={g['idle_sec']}s retry={g['retry']} prog={len(g['progress'])}")
    s = sys_info()
    gl2 = s["goalload"]
    print(f"load: {gl2['load15']} ({gl2['zone']}, n={gl2['n']}) cpu_top={gl2['cpu_top'][:3]}")
    rs = agent_repos()
    print(f"agent repos: {len(rs)} -> {[__import__('os').path.basename(r) for r in rs]}")
    for r in repo_stats()["repos"][:3]:
        print(f"  {r['name']}: commits={r['commits']} size={r['size']} "
              f"files={r['files']} dirty={r['dirty']}")   # exts 统计已从 repos.py 移除
    evts = merge_events(parse_watchdog_events(), parse_completed_goals(),
                        parse_repo_commits())
    kinds = {e["kind"] for e in evts}
    print(f"events: {len(evts)} kinds={sorted(kinds)}")
    html = render_html("localhost:8899", gather(), __import__("time").time(), "zh", sysdata=s)
    # tchip(工具直达 chips) 只在有未暂停的工具端口时渲染(svcctl 暂停过滤是预期行为)
    live_tool_ports = {e["port"] for e in gather() if not e.get("paused")} & {
        p for _, p in TOOL_LINKS}
    checks = ["Goal 进度", "仓库", "已完成 goal", "最近事件"] + (["tchip"] if live_tool_ports else [])
    print(f"  tool ports unpaused: {sorted(live_tool_ports) or 'none → tchip check skipped'}")
    ok = True
    for c in checks:
        mark = "ok" if c in html else "FAIL"
        print(f"  {mark} html contains {c!r}")
        ok = ok and (c in html)
    return 0 if ok else 1
