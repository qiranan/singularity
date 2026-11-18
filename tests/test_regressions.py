"""采集边界和命令行契约的回归测试，无需 root。"""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from singularity import cli, utils
from singularity.collectors import environments, logs, network, processes, users


PORT = {"proto": "tcp", "local_ip": "0.0.0.0", "port": 8080,
        "process": "demo", "user": "tester", "exposure": "public"}


class TestPortWatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "ports.json"
        patch = mock.patch.object(network, "_snapshot_path", return_value=self.path)
        patch.start()
        self.addCleanup(patch.stop)

    def watch(self, ports, update=True):
        with mock.patch.object(network, "listening_ports", return_value=ports):
            return network.port_watch(update)

    def test_first_run_only_creates_baseline(self):
        result = self.watch([PORT])
        self.assertTrue(result["first_run"])
        self.assertEqual(result["alerts"], [])
        self.assertEqual(result["added"], [])
        self.assertTrue(result["baseline_saved"])
        self.assertFalse(self.watch([PORT])["first_run"])

    def test_empty_baseline_is_still_a_baseline(self):
        self.watch([])
        result = self.watch([PORT])
        self.assertFalse(result["first_run"])
        self.assertEqual(result["added"], [PORT])
        self.assertEqual(len(result["alerts"]), 1)

    def test_preview_does_not_write(self):
        result = self.watch([PORT], update=False)
        self.assertFalse(result["baseline_saved"])
        self.assertFalse(self.path.exists())
        self.watch([])
        original = self.path.read_bytes()
        self.assertEqual(self.watch([PORT], update=False)["added"], [PORT])
        self.assertEqual(self.path.read_bytes(), original)

    def test_bad_snapshots_are_preserved(self):
        for content in ("{", "[]", '{"ports": []}', '{"ports": {"x": 1}}'):
            with self.subTest(content=content):
                self.path.write_text(content)
                result = self.watch([PORT])
                self.assertIn("error", result)
                self.assertEqual(self.path.read_text(), content)

    def test_process_change_and_removed_port(self):
        self.watch([PORT])
        result = self.watch([{**PORT, "process": "other"}])
        self.assertEqual(result["process_changed"][0]["after"], "other")
        self.assertEqual(len(result["alerts"]), 1)
        self.assertEqual(self.watch([])["removed"][0]["process"], "other")

    def test_failed_replace_preserves_baseline(self):
        self.watch([])
        original = self.path.read_bytes()
        with mock.patch.object(network.os, "replace", side_effect=OSError("disk full")):
            result = self.watch([PORT])
        self.assertIn("error", result)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(Path(self.tmp.name).iterdir()), [self.path])


class TestNetworkBoundaries(unittest.TestCase):
    def test_failed_firewall_read_is_unknown(self):
        with mock.patch.object(network, "which", side_effect=lambda n: "/bin/nft" if n == "nft" else None), \
             mock.patch.object(network, "run", return_value=(1, "", "Operation not permitted")):
            result = network.firewall_status()
        self.assertIsNone(result["backends"]["nftables"]["active"])
        self.assertIn("nftables", result["unknown"])
        self.assertNotIn("所有监听端口均对外暴露", result["note"])

    def test_invalid_rules_do_not_invoke_commands(self):
        for args in (("bad", 80), ("allow", 0), ("allow", 65536),
                     ("allow", 80, "icmp"), ("allow", 80, "tcp", "--help")):
            with self.subTest(args=args), mock.patch.object(network, "run") as run:
                self.assertFalse(network.firewall_rule(*args)["ok"])
                run.assert_not_called()

    def test_firewalld_deny_uses_source_and_drop(self):
        status = {"backends": {"firewalld": {"active": True}}, "manager": "firewalld"}
        with mock.patch.object(network, "firewall_status", return_value=status), \
             mock.patch.object(network, "run", return_value=(0, "success", "")) as run, \
             mock.patch.object(utils, "audit"):
            result = network.firewall_rule("deny", 8080, source="10.0.0.0/8")
        self.assertTrue(result["ok"])
        command = run.call_args_list[0].args[0]
        self.assertIn('source address="10.0.0.0/8"', command[-1])
        self.assertIn(" drop", command[-1])
        self.assertNotIn("--add-port=8080/tcp", command)

    def test_firewalld_failure_does_not_reload_or_succeed(self):
        status = {"backends": {"firewalld": {"active": True}}, "manager": "firewalld"}
        with mock.patch.object(network, "firewall_status", return_value=status), \
             mock.patch.object(network, "run", return_value=(1, "", "denied")) as run, \
             mock.patch.object(utils, "audit"):
            self.assertFalse(network.firewall_rule("allow", 8080)["ok"])
        self.assertEqual(run.call_count, 1)

    def test_nftables_never_falls_through_to_iptables(self):
        status = {"backends": {"nftables": {"active": True}}, "manager": "nftables"}
        with mock.patch.object(network, "firewall_status", return_value=status), \
             mock.patch.object(network, "run") as run:
            self.assertFalse(network.firewall_rule("allow", 8080)["ok"])
        run.assert_not_called()

    def test_invalid_bandwidth_interval(self):
        for interval in (0, -1, float("nan"), float("inf")):
            with self.subTest(interval=interval), mock.patch.object(network.time, "sleep") as sleep:
                with self.assertRaises(ValueError):
                    network.bandwidth(interval)
                sleep.assert_not_called()

    def test_counter_reset_never_gives_negative_bandwidth(self):
        with mock.patch.object(network, "_read_net_dev", side_effect=[{"eth0": (100, 100)}, {"eth0": (10, 20)}]), \
             mock.patch.object(network.time, "sleep"), \
             mock.patch.object(network.time, "monotonic", side_effect=[1.0, 3.0]), \
             mock.patch.object(network, "which", return_value=None):
            result = network.bandwidth(2)
        self.assertEqual(result["interfaces"][0]["rx_bps"], 0)
        self.assertEqual(result["interfaces"][0]["tx_bps"], 0)


class TestLogBoundaries(unittest.TestCase):
    def test_path_prefix_does_not_bypass_allowlist(self):
        with mock.patch.object(logs.os.path, "isfile", return_value=True), \
             mock.patch.object(logs.os, "access", return_value=True), \
             mock.patch.object(logs, "tail_file", return_value=[]) as tail:
            for path in ("/var/log-private/secret", "/opt-backup/secret", "/tmp-other/secret"):
                with self.subTest(path=path):
                    self.assertIn("error", logs.read_log(path))
            tail.assert_not_called()

    def test_invalid_regex_returns_actionable_error(self):
        self.assertIn("error", logs.search_logs("["))
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("ERROR example\n")
        self.addCleanup(os.unlink, f.name)
        # Linux 临时目录 /tmp 在允许的日志根目录内。
        if os.name == "posix":
            self.assertIn("error", logs.read_log(f.name, grep="["))

    def test_zero_tail_and_gzip_tail(self):
        import gzip
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.gz"
            with gzip.open(path, "wt") as f:
                f.write("one\ntwo\nthree\n")
            self.assertEqual(utils.tail_file(path, 0), [])
            self.assertEqual(utils.tail_file(path, 2), ["two", "three"])


class TestCLI(unittest.TestCase):
    def call(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_failed_operation_sets_exit_code(self):
        code, out, _ = self.call(["--json", "proc", "kill", "1"])
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(out)["ok"])

    def test_invalid_regex_is_json_and_nonzero(self):
        code, out, _ = self.call(["--json", "log", "search", "["])
        self.assertEqual(code, 1)
        self.assertIn("error", json.loads(out))

    def test_invalid_interval_is_json_and_nonzero(self):
        code, out, _ = self.call(["--json", "net", "bandwidth", "--interval", "0"])
        self.assertEqual(code, 1)
        self.assertIn("error", json.loads(out))

    def test_bare_modules_show_summary(self):
        # users / env 默认进入树状视图，其余模块默认概览
        for name, collector, func in (("users", users, "list_users"), ("net", network, "summary"),
                                      ("proc", processes, "summary"), ("env", environments, "dev_tree"),
                                      ("log", logs, "summary")):
            with self.subTest(module=name), \
                 mock.patch.object(collector, func, return_value={"module": name}) as collected:
                code, out, err = self.call(["--json", name])
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(out), {"module": name})
                self.assertEqual(err, "")
                collected.assert_called_once()
        with mock.patch.object(users, "list_users", return_value=[]) as listed:
            code, out, _ = self.call(["users"])
            self.assertEqual(code, 0)
            listed.assert_called_once_with(include_system=False)
        with mock.patch.object(environments, "dev_tree", return_value={"label": "开发环境", "children": []}) as tree:
            code, out, _ = self.call(["env"])
            self.assertEqual(code, 0)
            self.assertIn("开发环境", out)
            tree.assert_called_once_with(include_size=False, with_packages=0)

    def test_no_arguments_shows_help_successfully(self):
        code, out, err = self.call([])
        self.assertEqual(code, 0)
        self.assertIn("usage: singularity", out)
        self.assertIn("singularity env python", out)
        self.assertEqual(err, "")

    def test_version_matches_package(self):
        from singularity import __version__
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as caught:
            cli.main(["--version"])
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(stdout.getvalue().strip(), f"singularity {__version__}")

    def test_help_does_not_collect_data(self):
        with mock.patch.object(environments, "summary") as summary, \
             contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as caught:
            cli.main(["env", "--help"])
        self.assertEqual(caught.exception.code, 0)
        summary.assert_not_called()

    def test_missing_mutation_arguments_still_rejected(self):
        with mock.patch.object(processes, "kill_process") as kill, \
             contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            cli.main(["proc", "kill"])
        self.assertEqual(caught.exception.code, 2)
        kill.assert_not_called()


class TestEnvironmentAndLocale(unittest.TestCase):
    def test_clone_script_preserves_two_digit_minor_and_quotes_path(self):
        with mock.patch.object(environments, "run", return_value=(0, "", "")), \
             mock.patch.object(environments, "read_lines", return_value=["version = 3.14.8"]):
            result = environments.export_env("/tmp/my env")
        self.assertTrue(result["clone_script"].startswith("python3.14 -m venv 'my env'"))

    def test_parser_commands_force_c_locale(self):
        with mock.patch.dict(os.environ, {"LANG": "zh_CN.UTF-8", "LC_ALL": "zh_CN.UTF-8"}), \
             mock.patch.object(utils, "which", return_value="/bin/example"), \
             mock.patch.object(utils.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="", stderr="")) as run:
            utils.run(["example"])
            self.assertEqual(run.call_args.kwargs["env"]["LC_ALL"], "C")


if __name__ == "__main__":
    unittest.main()
