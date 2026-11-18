"""WSL/Linux 集成冒烟：python3 tests/smoke_wsl.py。只在临时目录写入测试状态。"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    if sys.platform != "linux":
        raise SystemExit("请在 WSL/Linux 中运行")
    checks = []
    with tempfile.TemporaryDirectory(prefix="singularity-smoke-") as tmp:
        state = Path(tmp)
        env = {**os.environ, "SINGULARITY_HOME": str(state / "state")}
        log = state / "example.log"
        log.write_text("INFO ready\nWARNING disk\nERROR example\n")
        requirements = state / "requirements.txt"
        requirements.write_text("example-package==1.0\n")

        def cli(args, expected=0):
            started = time.monotonic()
            proc = subprocess.run([sys.executable, "-m", "singularity", "--json", *args],
                                  cwd=ROOT, env=env, capture_output=True, text=True, timeout=90)
            assert proc.returncode == expected, (args, proc.returncode, proc.stderr, proc.stdout[-1000:])
            data = json.loads(proc.stdout)
            checks.append({"cli": " ".join(args).replace(tmp, "<tmp>"), "exit": proc.returncode,
                           "seconds": round(time.monotonic() - started, 2)})
            return data

        for args in (["overview"], ["users"], ["net"], ["proc"], ["env"], ["log"],
                     ["users", "list"], ["users", "risks"], ["users", "logins", "--hours", "1"],
                     ["net", "ports"], ["net", "conns"], ["net", "firewall"], ["net", "ifaces"],
                     ["net", "bandwidth", "--interval", "0.05"], ["proc", "list", "--limit", "5"],
                     ["proc", "services", "--failed"], ["proc", "cron"], ["env", "python", "--root", tmp],
                     ["env", "packages", "--no-upgradable"], ["env", "docker"],
                     ["env", "scan", str(requirements), "--offline"],
                     ["log", "list", "--top", "3"], ["log", "read", str(log), "--level", "warning"],
                     ["log", "rotate"], ["log", "anomalies", "--hours", "1"]):
            cli(args)
        cli(["net", "bandwidth", "--interval", "0"], expected=1)
        cli(["log", "search", "["], expected=1)
        cli(["proc", "kill", "1"], expected=1)

        baseline = cli(["net", "watch"])
        assert baseline["first_run"] and baseline["alerts"] == []
        before = (state / "state" / "ports_snapshot.json").read_bytes()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            added = cli(["net", "watch", "--no-update"])
            assert any(row["port"] == port for row in added["added"]), added
            assert (state / "state" / "ports_snapshot.json").read_bytes() == before
            cli(["net", "watch"])
        removed = cli(["net", "watch"])
        assert any(row["port"] == port for row in removed["removed"]), removed

        venv = state / "my env"
        cli(["env", "venv-create", str(venv)])
        exported = cli(["env", "export", str(venv)])
        assert exported["clone_script"].startswith(f"python{sys.version_info.major}.{sys.version_info.minor} ")
        tree = cli(["env", "tree", "--packages", "3"])
        assert tree["label"] == "开发环境" and any(ch["label"].startswith("Python") for ch in tree["children"]), tree
        cli(["env", "venv-delete", str(venv)])
        assert not venv.exists()

        groups = cli(["users", "groups", "--all"])
        assert any(g["group"] == "root" and g["level"] == "root" for g in groups), groups[:3]
        listed = cli(["users", "list", "--all"])
        root = next(u for u in listed if u["user"] == "root")
        assert root["max_level"] == "root" and root["primary_group"] == "root", root
    print(json.dumps({"platform": sys.platform, "python": sys.version.split()[0], "checks": checks,
                      "passed": len(checks)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
