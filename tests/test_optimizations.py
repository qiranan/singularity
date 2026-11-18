"""升级范围、并发克隆、日志窗口、审计和概览缓存的行为测试。"""
import contextlib
import datetime as dt
import io
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from singularity import cli, overview, utils
from singularity.collectors import environments, logs, users


class TestPackageUpgrade(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(utils, "audit")
        patch.start()
        self.addCleanup(patch.stop)

    def test_unsupported_security_filter_never_runs_upgrade(self):
        for manager in ("pacman", "apk", "zypper", ""):
            with self.subTest(manager=manager), mock.patch.object(environments, "_pkg_manager", return_value=manager), \
                 mock.patch.object(environments, "run") as run:
                self.assertFalse(environments.package_upgrade(security_only=True)["ok"])
                run.assert_not_called()

    def test_failed_index_refresh_stops_upgrade(self):
        with mock.patch.object(environments, "_pkg_manager", return_value="apt"), \
             mock.patch.object(environments, "run", return_value=(1, "", "repository unavailable")) as run:
            result = environments.package_upgrade(security_only=True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["stage"], "update")
        self.assertEqual(run.call_count, 1)

    def test_failed_security_query_is_not_no_updates(self):
        with mock.patch.object(environments, "_pkg_manager", return_value="apt"), \
             mock.patch.object(environments, "run", return_value=(0, "", "")) as run, \
             mock.patch.object(environments, "packages", return_value={"error": "query failed"}):
            self.assertFalse(environments.package_upgrade(security_only=True)["ok"])
        self.assertEqual(run.call_count, 1)

    def test_no_updates_is_explicitly_skipped(self):
        with mock.patch.object(environments, "_pkg_manager", return_value="apt"), \
             mock.patch.object(environments, "run", return_value=(0, "", "")) as run, \
             mock.patch.object(environments, "packages", return_value={"security": []}):
            result = environments.package_upgrade(security_only=True)
        self.assertTrue(result["ok"])
        self.assertTrue(result["skipped"])
        self.assertEqual(run.call_count, 1)

    def test_named_packages_still_obey_security_filter(self):
        with mock.patch.object(environments, "_pkg_manager", return_value="apt"), \
             mock.patch.object(environments, "run", return_value=(0, "", "")) as run, \
             mock.patch.object(environments, "packages", return_value={"security": [{"name": "openssl"}, {"name": "curl"}]}):
            environments.package_upgrade(["openssl", "nginx"], security_only=True)
        self.assertEqual(run.call_args.args[0], ["apt-get", "install", "-y", "--only-upgrade", "openssl"])
        with mock.patch.object(environments, "_pkg_manager", return_value="dnf"), \
             mock.patch.object(environments, "run", return_value=(0, "", "")) as run:
            environments.package_upgrade(["openssl"], security_only=True)
        self.assertIn("--security", run.call_args.args[0])

    def test_bad_package_name_never_executes(self):
        with mock.patch.object(environments, "run") as run:
            self.assertFalse(environments.package_upgrade(["--help"])["ok"])
            run.assert_not_called()


class TestCloneIsolation(unittest.TestCase):
    def test_simultaneous_clones_have_independent_cleaned_manifests(self):
        barrier = threading.Barrier(2)
        observed, paths = {}, []

        def install(cmd, **kwargs):
            paths.append(Path(cmd[-1]))
            barrier.wait(timeout=5)
            observed[cmd[0]] = Path(cmd[-1]).read_text()
            return 0, "", ""

        with mock.patch.object(environments, "export_env", side_effect=lambda source: {"ok": True, "requirements": source + "==1\n"}), \
             mock.patch.object(environments, "create_venv", return_value={"ok": True}), \
             mock.patch.object(environments, "run", side_effect=install), mock.patch.object(utils, "audit"):
            with ThreadPoolExecutor(max_workers=2) as pool:
                pending = [pool.submit(environments.clone_env, source, "/" + source) for source in ("a", "b")]
                self.assertTrue(all(task.result(timeout=10)["ok"] for task in pending))
        self.assertEqual(observed, {"/a/bin/pip": "a==1\n", "/b/bin/pip": "b==1\n"})
        self.assertNotEqual(paths[0], paths[1])
        self.assertTrue(all(not path.exists() for path in paths))


class TestLogWindows(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 1, 1, 0, 30, tzinfo=dt.timezone.utc)

    def test_iso_and_syslog_year_boundary(self):
        lines = ["2020-01-01T00:00:00+0000 old", "2025-12-31T23:45:00Z recent",
                 "Dec 31 23:50:00 host recent", "Jan  1 00:20:00 host recent",
                 "2026-01-01T01:00:00+0000 future", "unrecognized event"]
        recent, unknown = utils.recent_log_lines(lines, 1, self.now)
        self.assertEqual(recent, lines[1:4])
        self.assertEqual(unknown, 1)

    def test_continuations_keep_parent_time(self):
        lines = ["2020-01-01T00:00:00 old", " old continuation",
                 "2026-01-01T00:00:00 recent", " recent continuation"]
        self.assertEqual(utils.recent_log_lines(lines, 1, self.now)[0], lines[2:])

    def test_old_file_events_are_not_counted_in_one_hour(self):
        old = "2020-01-01T00:00:00+0000 host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2"
        with mock.patch.object(logs, "which", return_value=None), \
             mock.patch.object(logs.os.path, "isfile", side_effect=lambda p: p == "/var/log/auth.log"), \
             mock.patch.object(logs.os, "access", return_value=True), \
             mock.patch.object(logs, "tail_file", return_value=[old]), mock.patch.object(logs, "run", return_value=(0, "", "")):
            self.assertEqual(logs.anomalies(1)["groups"], [])
        with mock.patch.object(users, "which", return_value=None), \
             mock.patch.object(users.os.path, "isfile", return_value=True), \
             mock.patch.object(users, "tail_file", return_value=[old]), mock.patch.object(users, "run", return_value=(0, "", "")):
            self.assertEqual(users.login_audit(1)["ssh_failed_by_ip"], [])

    def test_successful_empty_journal_does_not_fall_back(self):
        for collector, collect in ((logs, logs.anomalies), (users, users.login_audit)):
            with self.subTest(collector=collector.__name__), mock.patch.object(collector, "which", return_value="/bin/tool"), \
                 mock.patch.object(collector, "run", return_value=(0, "", "")), \
                 mock.patch.object(collector, "tail_file") as tail:
                collect(1)
                tail.assert_not_called()


class TestAuditResults(unittest.TestCase):
    def test_failure_does_not_erase_operation_result(self):
        with mock.patch.object(utils, "audit", side_effect=OSError("disk full")):
            result = utils.audit_result("test", {"ok": True, "pid": 123})
        self.assertTrue(result["ok"])
        self.assertEqual(result["pid"], 123)
        self.assertIn("disk full", result["audit_error"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.emit(mock.Mock(json=True), result), 1)

    def test_rotation_keeps_latest_and_bounded_backups(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(utils, "DATA_DIR", Path(tmp)), \
             mock.patch.object(utils, "AUDIT_MAX_BYTES", 1):
            for index in range(6):
                utils.audit("test", {"index": index})
            self.assertEqual(json.loads((Path(tmp) / "audit.log").read_text())["detail"]["index"], 5)
            self.assertEqual(len(list(Path(tmp).glob("audit.log*"))), 4)


class TestOverview(unittest.TestCase):
    def test_parallel_modules_and_partial_failure(self):
        barrier = threading.Barrier(5)

        def collect(name):
            barrier.wait(timeout=5)
            if name == "network":
                raise OSError("unavailable")
            return {"module": name}

        with contextlib.ExitStack() as stack:
            for name, module in overview.MODULES.items():
                stack.enter_context(mock.patch.object(module, "summary", side_effect=lambda name=name: collect(name)))
            result = overview.collect()
        self.assertEqual(result["network"]["error"], "unavailable")
        self.assertEqual(result["users"]["module"], "users")
        self.assertEqual(result["logs"]["module"], "logs")
        self.assertTrue(all("collected_at" in value for value in result.values()))

    def test_environment_summary_skips_expensive_details(self):
        with mock.patch.object(environments, "python_envs", return_value={"venvs": [], "conda": [], "system": []}) as discover, \
             mock.patch.object(environments, "packages", return_value={"manager": "apt", "upgradable_count": 0, "security_count": 0, "reboot_required": False}), \
             mock.patch.object(environments, "which", return_value="docker"), \
             mock.patch.object(environments, "run", return_value=(0, '{"Containers":3,"ContainersRunning":2}', "")), \
             mock.patch.object(environments, "docker_info") as details:
            result = environments.summary()
        discover.assert_called_once_with(include_size=False)
        details.assert_not_called()
        self.assertEqual(result["docker"], {"containers": 3, "running": 2})


class TestManifestDiscovery(unittest.TestCase):
    def test_nested_manifests_are_not_pruned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "child").mkdir()
            for parent in (root, root / "child"):
                (parent / "requirements.txt").touch()
            self.assertEqual(set(environments._walk_find("requirements.txt", [tmp])), {tmp, str(root / "child")})


if __name__ == "__main__":
    unittest.main()
