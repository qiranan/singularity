"""解析器单元测试：用真实 Linux 命令输出样本验证，可在任意平台运行。  python -m unittest tests/test_parsers.py"""
import contextlib
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from singularity.collectors import users, network, processes, environments, logs  # noqa: E402

SS_OUT = """tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      511        127.0.0.1:6379      0.0.0.0:*    users:(("redis-server",pid=1200,fd=6))
tcp   LISTEN 0      4096             *:3306            *:*    users:(("mysqld",pid=1501,fd=22))
udp   UNCONN 0      0        127.0.0.53%lo:53        0.0.0.0:*    users:(("systemd-resolve",pid=600,fd=13))
tcp   LISTEN 0      128             [::]:22           [::]:*    users:(("sshd",pid=812,fd=4))
"""

CRONTAB = """SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin
# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
*/5 * * * * www-data /usr/bin/php /var/www/artisan schedule:run
@reboot root /usr/local/bin/start.sh
"""

SUDOERS = """Defaults env_reset
root    ALL=(ALL:ALL) ALL
%sudo   ALL=(ALL:ALL) ALL
deploy  ALL=(ALL) NOPASSWD: ALL
backup  ALL=(root) NOPASSWD: /usr/bin/rsync, /usr/bin/vim
"""

APT_LIST = """Listing... Done
openssl/jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.14]
curl/jammy-updates 7.81.0-1ubuntu1.16 amd64 [upgradable from: 7.81.0-1ubuntu1.15]
"""

JOURNAL = """2026-11-03T02:10:11+0800 host kernel: Out of memory: Killed process 4321 (java) total-vm:8000000kB
2026-11-03T02:10:12+0800 host systemd[1]: myapp.service: Main process exited, code=exited, status=137/n/a
2026-11-03T02:10:12+0800 host systemd[1]: myapp.service: Failed with result 'oom-kill'.
2026-11-03T02:10:20+0800 host sshd[999]: Failed password for invalid user admin from 10.0.0.5 port 4444 ssh2
2026-11-03T02:10:21+0800 host sshd[999]: Failed password for root from 10.0.0.5 port 4445 ssh2
2026-11-03T03:00:00+0800 host sshd[1001]: Accepted publickey for deploy from 10.0.0.9 port 5555 ssh2
"""


class TestNetwork(unittest.TestCase):
    def test_ss_parse(self):
        with mock.patch.object(network, "run", return_value=(0, SS_OUT, "")), \
             mock.patch.object(network, "pid_user", return_value="root"), \
             mock.patch.object(network, "pid_cmdline", return_value="/usr/sbin/sshd -D"):
            rows = network.listening_ports()
        by_port = {(r["proto"], r["port"], r["local_ip"]): r for r in rows}
        self.assertEqual(by_port[("tcp", 22, "0.0.0.0")]["process"], "sshd")
        self.assertEqual(by_port[("tcp", 22, "0.0.0.0")]["exposure"], "public")
        self.assertEqual(by_port[("tcp", 6379, "127.0.0.1")]["exposure"], "local")
        self.assertEqual(by_port[("tcp", 6379, "127.0.0.1")]["risk"], "")
        self.assertEqual(by_port[("tcp", 3306, "*")]["risk"], "high")
        self.assertEqual(by_port[("udp", 53, "127.0.0.53")]["process"], "systemd-resolve")
        self.assertEqual(by_port[("tcp", 22, "::")]["pid"], 812)

    def test_hex_addr(self):
        self.assertEqual(network._hex_addr("0100007F:1F90", False), ("127.0.0.1", 8080))
        self.assertEqual(network._hex_addr("00000000000000000000000001000000:0016", True), ("::1", 22))


class TestUsers(unittest.TestCase):
    def test_sudo(self):
        with mock.patch.object(users, "read_lines", side_effect=lambda p: SUDOERS.splitlines() if p == "/etc/sudoers" else []), \
             mock.patch.object(users.os, "access", return_value=True), \
             mock.patch.object(users.glob, "glob", return_value=[]):
            d = users.sudo_audit()
        who = {r["who"]: r for r in d["rules"]}
        self.assertTrue(who["deploy"]["nopasswd"])
        self.assertEqual(who["backup"]["commands"], ["/usr/bin/rsync", "/usr/bin/vim"])
        msgs = " ".join(f["msg"] for f in d["findings"])
        self.assertIn("deploy 免密", msgs)
        self.assertIn("vim", msgs)

    def test_fingerprint(self):
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq5nQq8d3o1n8Q9Zc0v2X1Y5Y3jBqgI3fKX3vYg6m2G user@host"
        t, fp, c = users._fingerprint(key)
        self.assertEqual(t, "ssh-ed25519")
        self.assertTrue(fp.startswith("SHA256:"))
        self.assertEqual(c, "user@host")
        t, fp, c = users._fingerprint('from="10.0.0.1" ' + key)
        self.assertIn("opts", c)

    def test_sshd_config(self):
        with mock.patch.object(users, "read_lines", return_value=["# comment", "PermitRootLogin yes", "Port 2222", "PermitRootLogin no"]), \
             mock.patch.object(users.glob, "glob", return_value=[]):
            conf = users._sshd_config()
        self.assertEqual(conf["permitrootlogin"], "yes")  # 首个生效
        self.assertEqual(conf["port"], "2222")

    def test_parse_last(self):
        out = ("deploy   pts/0        10.0.0.9         Tue Nov  3 03:00:00 2026 - Tue Nov  3 03:30:00 2026  (00:30)\n"
               "reboot   system boot  5.15.0-91-generic Mon Nov  2 10:00:00 2026   still running\n\n"
               "wtmp begins Mon Oct  1 00:00:00 2026\n")
        rows = users._parse_last(out)
        self.assertEqual(rows[0]["user"], "deploy")
        self.assertEqual(rows[0]["ip"], "10.0.0.9")


class TestProcesses(unittest.TestCase):
    def test_cron_parse(self):
        jobs = processes._parse_cron_lines(CRONTAB.splitlines(), "/etc/crontab", None, True)
        self.assertEqual(len(jobs), 4)
        self.assertEqual(jobs[2]["user"], "www-data")
        self.assertEqual(jobs[2]["description"], "每 5 分钟")
        self.assertEqual(jobs[3]["schedule"], "@reboot")
        self.assertEqual(jobs[1]["description"], "每天 06:25")
        user_jobs = processes._parse_cron_lines(["0 3 * * 0 /backup.sh"], "/var/spool/cron/crontabs/bob", "bob", False)
        self.assertEqual(user_jobs[0]["user"], "bob")
        self.assertEqual(user_jobs[0]["command"], "/backup.sh")

    def test_services_parse(self):
        units = "ssh.service loaded active running OpenBSD Secure Shell server\nfoo.service loaded failed failed Foo daemon\n"
        files = "ssh.service enabled enabled\nfoo.service disabled enabled\n"
        with mock.patch.object(processes, "run", side_effect=[(0, files, ""), (0, units, "")]), \
             mock.patch.object(processes, "which", return_value="/bin/systemctl"):
            svc = processes.services()
        self.assertEqual(svc[0]["enabled"], "enabled")
        self.assertEqual(svc[1]["active"], "failed")
        self.assertEqual(svc[1]["description"], "Foo daemon")

    def test_read_stat(self):
        raw = "1234 (my prog (x)) S 1 1234 1234 0 -1 4194560 100 0 0 0 50 25 0 0 20 0 3 0 9999 123456789 300 1 2 3 4 5 6 7 8 9 10"
        with mock.patch.object(processes, "read_text", return_value=raw):
            st = processes._read_stat(1234)
        self.assertEqual(st["comm"], "my prog (x)")
        self.assertEqual(st["state"], "S")
        self.assertEqual(st["utime"], 50)
        self.assertEqual(st["threads"], 3)


class TestEnvironments(unittest.TestCase):
    def test_apt_upgradable(self):
        def fake_run(cmd, **kw):
            if cmd[0] == "dpkg-query":
                return 0, "a\nb\nc\n", ""
            if cmd[:2] == ["apt", "list"]:
                return 0, APT_LIST, ""
            return 1, "", ""
        with mock.patch.object(environments, "_pkg_manager", return_value="apt"), \
             mock.patch.object(environments, "run", side_effect=fake_run):
            d = environments.packages()
        self.assertEqual(d["installed_count"], 3)
        self.assertEqual(d["upgradable_count"], 2)
        self.assertEqual(d["security_count"], 1)
        self.assertEqual(d["security"][0]["name"], "openssl")
        self.assertEqual(d["upgradable"][1]["current"], "7.81.0-1ubuntu1.15")

    def test_requirements(self):
        with mock.patch.object(environments, "read_lines", return_value=["requests==2.31.0  # http", "Django[argon2]==4.2", "flask>=2"]):
            deps = environments._parse_requirements("x")
        self.assertEqual(deps, [("requests", "2.31.0"), ("django", "4.2")])


class TestLogs(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(logs._level_of("kernel: Out of memory"), "info")
        self.assertEqual(logs._level_of("[ERROR] boom"), "error")
        self.assertEqual(logs._level_of("WARNING: disk"), "warning")
        self.assertEqual(logs._level_of("CRIT something"), "critical")

    def test_anomalies(self):
        with mock.patch.object(logs, "which", side_effect=lambda n: "/bin/x" if n == "journalctl" else None), \
             mock.patch.object(logs, "run", side_effect=lambda cmd, **kw: (0, JOURNAL, "") if "-p" in cmd else (0, "", "")):
            d = logs.anomalies(24)
        keys = {g["key"]: g for g in d["groups"]}
        self.assertEqual(keys["oom"]["count"], 1)
        self.assertEqual(keys["service_failed"]["count"], 1)
        self.assertEqual(keys["service_restart"]["count"], 1)
        self.assertEqual(keys["auth_failure"]["count"], 2)
        self.assertEqual(d["groups"][0]["level"], "critical")  # 排序：最严重在前

    def test_logrotate_parse(self):
        content = ["compress", "/var/log/app/*.log /var/log/other.log {", "  weekly", "  rotate 4", "  missingok", "}"]
        with mock.patch.object(logs, "read_lines", return_value=content):
            blocks, g = logs._parse_logrotate("/etc/logrotate.d/app")
        self.assertEqual(g, {"compress": True})
        self.assertEqual(blocks[0]["files"], ["/var/log/app/*.log", "/var/log/other.log"])
        self.assertEqual(blocks[0]["options"]["rotate"], "4")

    def test_login_audit_parsing(self):
        def fake_run(cmd, **kw):
            if cmd[0] == "journalctl":
                return 0, JOURNAL, ""
            if cmd[0] == "who":
                return 0, "deploy   pts/0        2026-11-03 03:00 (10.0.0.9)\n", ""
            return 0, "", ""
        with mock.patch.object(users, "run", side_effect=fake_run), mock.patch.object(users, "which", return_value="/bin/j"):
            d = users.login_audit(24)
        self.assertEqual(d["online"][0]["from"], "10.0.0.9")
        self.assertEqual(dict(d["ssh_failed_by_ip"])["10.0.0.5"], 2)
        self.assertEqual(d["ssh_accepted"][0]["user"], "deploy")
        self.assertTrue(any("非工作时间" in a["msg"] for a in d["alerts"]))


PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/zsh
deploy:x:1002:1002::/home/deploy:/bin/bash
"""
GROUP = """root:x:0:
daemon:x:1:
adm:x:4:alice
sudo:x:27:alice
www-data:x:33:
docker:x:999:bob
alice:x:1000:
bob:x:1001:
deploy:x:1002:
devs:x:2000:alice,bob
"""


class TestGroupsAndPrivileges(unittest.TestCase):
    def _patch(self):
        files = {"/etc/passwd": PASSWD, "/etc/group": GROUP, "/etc/sudoers": SUDOERS, "/etc/shadow": ""}
        return (mock.patch.object(users, "read_lines", side_effect=lambda p: files.get(str(p), "").splitlines()),
                mock.patch.object(users.os, "access", return_value=True),
                mock.patch.object(users.glob, "glob", return_value=[]),
                mock.patch.object(users.os.path, "isdir", return_value=True))

    def test_list_users_privileges(self):
        with contextlib.ExitStack() as stack:
            for p in self._patch():
                stack.enter_context(p)
            us = {u["user"]: u for u in users.list_users()}
            visible = users.list_users(include_system=False)
        self.assertEqual(us["root"]["max_level"], "root")
        self.assertEqual(us["root"]["primary_group"], "root")
        # alice: sudo 组 → %sudo 规则 → root
        self.assertEqual(us["alice"]["groups"], ["alice", "adm", "sudo", "devs"])
        self.assertEqual(us["alice"]["max_level"], "root")
        self.assertEqual([r["via"] for r in us["alice"]["sudo_rules"]], ["%sudo"])
        self.assertTrue(any("sudo 任意命令" in p["desc"] for p in us["alice"]["privileges"]))
        self.assertTrue(any(p["source"] == "组 adm" for p in us["alice"]["privileges"]))
        # bob: docker 组 → root 等价，无 sudo 规则
        self.assertEqual(us["bob"]["max_level"], "root-equiv")
        self.assertEqual(us["bob"]["sudo_rules"], [])
        # deploy: 直接 NOPASSWD ALL
        self.assertEqual(us["deploy"]["max_level"], "root")
        self.assertIn("免密", us["deploy"]["privileges"][0]["desc"])
        self.assertEqual(us["deploy"]["sudo_rules"][0]["via"], "user")
        # 系统账号过滤与排序：高权限在前
        self.assertNotIn("daemon", {u["user"] for u in visible})
        self.assertEqual([u["user"] for u in visible][:1], ["root"])

    def test_groups_view(self):
        with contextlib.ExitStack() as stack:
            for p in self._patch():
                stack.enter_context(p)
            gs = {g["group"]: g for g in users.groups_view()}
            all_gs = {g["group"]: g for g in users.groups_view(include_empty=True)}
        self.assertEqual([m["user"] for m in gs["sudo"]["members"]], ["alice"])
        self.assertEqual(gs["sudo"]["level"], "root")
        self.assertEqual(gs["sudo"]["sudo_rules"], ["%sudo   ALL=(ALL:ALL) ALL"])
        self.assertEqual(gs["docker"]["level"], "root-equiv")
        self.assertEqual(gs["devs"]["level"], "normal")
        self.assertEqual({m["user"] for m in gs["devs"]["members"]}, {"alice", "bob"})
        self.assertTrue(gs["alice"]["is_private"])
        self.assertTrue(gs["root"]["members"][0]["primary"])
        self.assertIn("daemon", gs)          # 系统组有主组成员 daemon → 保留
        self.assertEqual(gs["daemon"]["level"], "service")
        self.assertIn("daemon", all_gs)
        # 排序：root 级在最前
        levels = [g["level"] for g in all_gs.values()]
        self.assertEqual(levels[0], "root")
        self.assertEqual(levels, sorted(levels, key=users.PRIV_ORDER.index))

    def test_group_privilege_fallbacks(self):
        self.assertEqual(users._group_privilege("sudo")[0], "root")
        self.assertEqual(users._group_privilege("mygrp", 0)[0], "root")
        self.assertEqual(users._group_privilege("svc", 500)[0], "service")
        self.assertEqual(users._group_privilege("team", 3000)[0], "normal")


class TestTree(unittest.TestCase):
    def test_render_tree(self):
        from singularity import cli
        with mock.patch.object(cli, "USE_COLOR", False):
            lines = cli.render_tree({"label": "开发环境", "note": "host", "children": [
                {"label": "Python 3.12", "children": [{"label": "venv (1)", "children": [{"label": "/opt/app/.venv", "note": "45 包"}]}]},
                {"label": "Docker 26"}]})
        self.assertEqual(lines, [
            "开发环境  host",
            "├── Python 3.12",
            "│   └── venv (1)",
            "│       └── /opt/app/.venv  45 包",
            "└── Docker 26",
        ])

    def test_dev_tree_structure(self):
        py = {"venvs": [{"path": "/opt/app/.venv", "python": "3.12.3", "base": "/usr", "packages": 45, "size": None, "owner": "alice", "has_pip": True}],
              "conda": [], "pyenv": [{"kind": "pyenv", "path": "/home/alice/.pyenv/versions/3.11.9", "python": "3.11.9", "owner": "alice"}],
              "system": [{"name": "python3", "path": "/usr/bin/python3.12", "version": "3.12.3"}], "tools": {}, "scanned_roots": ["/opt"]}
        other = {"runtimes": {"go": {"path": "/usr/bin/go", "version": "1.22.1"}, "rustc": {"path": "/usr/bin/rustc", "version": "1.77.0"}},
                 "managers": {"rustup": [{"user": "alice", "path": "/home/alice/.rustup/toolchains/stable-x86_64-unknown-linux-gnu"}]}}
        node = {"system": {"node": {"path": "/usr/bin/node", "version": "v20.11.1"}}, "versions": [], "global_packages": [{"name": "pm2", "version": "5.3.0"}], "projects": []}
        with mock.patch.object(environments, "python_envs", return_value=py), \
             mock.patch.object(environments, "other_languages", return_value=other), \
             mock.patch.object(environments, "node_envs", return_value=node), \
             mock.patch.object(environments, "which", return_value=None), \
             mock.patch.object(environments.glob, "glob", return_value=[]), \
             mock.patch.object(environments, "home_dirs", return_value=[]), \
             mock.patch.object(environments, "read_text", return_value=""), \
             mock.patch.object(environments, "read_lines", return_value=[]), \
             mock.patch.object(environments, "packages", return_value={"manager": "", "installed_count": 0}):
            tree = environments.dev_tree()
        labels = [c["label"] for c in tree["children"]]
        self.assertEqual(tree["label"], "开发环境")
        self.assertEqual(labels, ["Python 3.12.3", "Node.js 20.11.1", "Go 1.22.1", "Rust 1.77.0"])
        python = tree["children"][0]
        sub = {c["label"]: c for c in python["children"]}
        self.assertIn("系统解释器 (1)", sub)
        self.assertEqual(sub["venv (1)"]["children"][0]["label"], "/opt/app/.venv")
        self.assertIn("45 包", sub["venv (1)"]["children"][0]["note"])
        self.assertEqual(sub["pyenv (alice)"]["children"][0]["label"], "3.11.9")
        rust = tree["children"][3]
        self.assertEqual(rust["children"][-1]["label"], "rustup (alice)")
        self.assertEqual(rust["children"][-1]["children"][0]["label"], "stable-x86_64-unknown-linux-gnu")


if __name__ == "__main__":
    unittest.main()
