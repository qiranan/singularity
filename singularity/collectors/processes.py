"""模块3：进程与服务 —— 进程列表/kill、systemd 服务管理、定时任务、开机启动项。"""
from __future__ import annotations

import glob
import os
import re
import signal
import time

from ..utils import run, which, read_lines, read_text, pid_user, pid_cmdline, audit_result, human_bytes

PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100


# ---------------------------------------------------------------- 进程
def _read_stat(pid: int) -> dict | None:
    raw = read_text(f"/proc/{pid}/stat")
    if not raw:
        return None
    # comm 可能含空格/括号，用最后一个 ')' 切分
    lp, rp = raw.find("("), raw.rfind(")")
    comm = raw[lp + 1:rp]
    f = raw[rp + 2:].split()
    return {"pid": pid, "comm": comm, "state": f[0], "ppid": int(f[1]), "utime": int(f[11]), "stime": int(f[12]),
            "threads": int(f[17]), "starttime": int(f[19]), "rss": int(f[21]) * PAGE}


def _total_jiffies() -> int:
    first = read_lines("/proc/stat")[0].split()[1:]
    return sum(int(x) for x in first)


def _mem_total() -> int:
    for line in read_lines("/proc/meminfo"):
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) * 1024
    return 1


def list_processes(sort_by: str = "cpu", limit: int = 50, interval: float = 0.5, user: str | None = None,
                   search: str | None = None) -> dict:
    """通过两次采样 /proc 计算 CPU 占用。"""
    pids = [int(p) for p in os.listdir("/proc") if p.isdigit()]
    t0 = _total_jiffies()
    s0 = {p: _read_stat(p) for p in pids}
    time.sleep(interval)
    t1 = _total_jiffies()
    ncpu = os.cpu_count() or 1
    mem_total = _mem_total()
    delta_total = max(1, t1 - t0)
    procs, zombies = [], []
    uptime = float(read_text("/proc/uptime").split()[0] or 0)
    for pid, a in s0.items():
        if not a:
            continue
        b = _read_stat(pid) or a
        cpu = (b["utime"] + b["stime"] - a["utime"] - a["stime"]) / delta_total * 100 * ncpu
        owner = pid_user(pid)
        if user and owner != user:
            continue
        item = {
            "pid": pid, "ppid": b["ppid"], "user": owner, "name": b["comm"], "state": b["state"],
            "cpu": round(cpu, 1), "mem": round(b["rss"] / mem_total * 100, 2), "rss": b["rss"],
            "rss_human": human_bytes(b["rss"]), "threads": b["threads"],
            "running_sec": int(uptime - b["starttime"] / CLK_TCK), "cmdline": pid_cmdline(pid)[:200],
        }
        if search and search.lower() not in (item["name"] + item["cmdline"]).lower():
            continue
        procs.append(item)
        if b["state"] == "Z":
            zombies.append(item)
    key = {"cpu": "cpu", "mem": "mem", "rss": "rss", "pid": "pid", "time": "running_sec"}.get(sort_by, "cpu")
    procs.sort(key=lambda x: x[key], reverse=key != "pid")
    load = read_text("/proc/loadavg").split()[:3]
    return {"processes": procs[:limit], "total": len(procs), "zombies": zombies, "load": load, "cpus": ncpu}


def kill_process(pid: int, sig: str = "TERM", actor: str = "cli") -> dict:
    signum = getattr(signal, f"SIG{sig.upper()}", None) if not str(sig).isdigit() else int(sig)
    if signum is None:
        return {"ok": False, "error": f"unknown signal {sig}"}
    if pid <= 1:
        return {"ok": False, "error": "refuse to kill pid <= 1"}
    name = pid_cmdline(pid)
    try:
        os.kill(pid, signum)
        return audit_result("kill", {"ok": True, "pid": pid, "signal": sig, "cmdline": name}, actor)
    except ProcessLookupError:
        return {"ok": False, "error": "no such process"}
    except PermissionError:
        return {"ok": False, "error": "permission denied"}


def process_tree(root: int = 1, max_depth: int = 6) -> list[dict]:
    children = {}
    for p in os.listdir("/proc"):
        if p.isdigit():
            st = _read_stat(int(p))
            if st:
                children.setdefault(st["ppid"], []).append(st)

    def build(pid, depth):
        node = {"pid": pid, "name": pid_cmdline(pid)[:80], "user": pid_user(pid), "children": []}
        if depth < max_depth:
            for c in sorted(children.get(pid, []), key=lambda s: s["pid"]):
                node["children"].append(build(c["pid"], depth + 1))
        return node
    return [build(root, 0)]


# ---------------------------------------------------------------- systemd 服务
def services(only_failed: bool = False, pattern: str | None = None) -> list[dict]:
    if not which("systemctl"):
        return _sysv_services()
    enabled = {}
    for line in run(["systemctl", "list-unit-files", "--type=service", "--no-pager", "--no-legend", "--plain"])[1].splitlines():
        p = line.split()
        if len(p) >= 2:
            enabled[p[0]] = p[1]
    out = []
    rc, text, _ = run(["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend", "--plain"])
    for line in text.splitlines():
        p = line.split(None, 4)
        if len(p) < 4:
            continue
        unit, load, active, sub = p[0], p[1], p[2], p[3]
        desc = p[4] if len(p) > 4 else ""
        if only_failed and active != "failed":
            continue
        if pattern and pattern.lower() not in (unit + desc).lower():
            continue
        out.append({"unit": unit, "load": load, "active": active, "sub": sub, "enabled": enabled.get(unit, "-"), "description": desc})
    return out


def _sysv_services() -> list[dict]:
    out = []
    for f in sorted(glob.glob("/etc/init.d/*")):
        name = os.path.basename(f)
        rc, text, _ = run([f, "status"], timeout=5)
        out.append({"unit": name, "load": "sysv", "active": "active" if rc == 0 else "inactive", "sub": "-",
                    "enabled": "yes" if glob.glob(f"/etc/rc[2-5].d/S*{name}") else "no", "description": ""})
    return out


def service_detail(name: str) -> dict:
    rc, out, err = run(["systemctl", "show", name, "--no-pager",
                        "-p", "Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID,ExecMainStartTimestamp,"
                              "NRestarts,MemoryCurrent,CPUUsageNSec,FragmentPath,Restart,User,ExecStart,Result"])
    props = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    if props.get("MemoryCurrent", "").isdigit():
        props["MemoryHuman"] = human_bytes(int(props["MemoryCurrent"]))
    props["status_text"] = run(["systemctl", "status", name, "--no-pager", "-n", "0"])[1]
    return props


SERVICE_ACTIONS = {"start", "stop", "restart", "reload", "enable", "disable", "mask", "unmask"}


def service_action(name: str, action: str, actor: str = "cli") -> dict:
    if action not in SERVICE_ACTIONS:
        return {"ok": False, "error": f"action must be one of {sorted(SERVICE_ACTIONS)}"}
    if not re.match(r"^[\w.@:-]+$", name):
        return {"ok": False, "error": "invalid unit name"}
    rc, out, err = run(["systemctl", action, name], timeout=60)
    return audit_result("service", {"ok": rc == 0, "unit": name, "action": action, "output": (out + err).strip(),
                        "state": service_detail(name).get("ActiveState")}, actor)


def service_logs(name: str, lines: int = 100, since: str | None = None) -> list[str]:
    cmd = ["journalctl", "-u", name, "--no-pager", "-o", "short-iso", "-n", str(lines)]
    if since:
        cmd += ["--since", since]
    return run(cmd, timeout=30)[1].splitlines()


# ---------------------------------------------------------------- 定时任务
CRON_RE = re.compile(r"^(@\w+|(?:\S+\s+){4}\S+)\s+(.*)$")


def _parse_cron_lines(lines: list[str], source: str, user: str | None, has_user_col: bool) -> list[dict]:
    jobs, env = [], {}
    for ln, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^\w+=", line):
            k, v = line.split("=", 1)
            env[k] = v.strip('"')
            continue
        m = CRON_RE.match(line)
        if not m:
            continue
        sched, rest = m.groups()
        if has_user_col:
            p = rest.split(None, 1)
            if len(p) == 2:
                job_user, cmd = p
            else:
                job_user, cmd = p[0], ""
        else:
            job_user, cmd = user, rest
        jobs.append({"source": source, "line": ln, "user": job_user, "schedule": sched, "command": cmd,
                     "description": describe_schedule(sched)})
    return jobs


def describe_schedule(s: str) -> str:
    specials = {"@reboot": "开机时", "@hourly": "每小时", "@daily": "每天 0:00", "@midnight": "每天 0:00",
                "@weekly": "每周日 0:00", "@monthly": "每月1日 0:00", "@yearly": "每年1月1日", "@annually": "每年1月1日"}
    if s in specials:
        return specials[s]
    f = s.split()
    if len(f) != 5:
        return s
    mi, h, dom, mon, dow = f
    if dom == mon == dow == "*":
        if h == "*" and mi.startswith("*/"):
            return f"每 {mi[2:]} 分钟"
        if h == "*" and mi == "*":
            return "每分钟"
        if h.startswith("*/"):
            return f"每 {h[2:]} 小时的第 {mi} 分"
        if h.isdigit() and mi.isdigit():
            return f"每天 {int(h):02d}:{int(mi):02d}"
    if dow != "*" and dom == "*" and h.isdigit() and mi.isdigit():
        return f"每周 {dow} 的 {int(h):02d}:{int(mi):02d}"
    if dom != "*" and dow == "*" and h.isdigit() and mi.isdigit():
        return f"每月 {dom} 日 {int(h):02d}:{int(mi):02d}"
    return s


def cron_jobs() -> dict:
    jobs = []
    jobs += _parse_cron_lines(read_lines("/etc/crontab"), "/etc/crontab", None, True)
    for f in sorted(glob.glob("/etc/cron.d/*")):
        if os.path.isfile(f) and not f.endswith((".dpkg-old", "~")):
            jobs += _parse_cron_lines(read_lines(f), f, None, True)
    for spool in ("/var/spool/cron/crontabs", "/var/spool/cron"):
        if os.path.isdir(spool):
            for f in sorted(glob.glob(spool + "/*")):
                if os.path.isfile(f):
                    jobs += _parse_cron_lines(read_lines(f), f, os.path.basename(f), False)
    periodic = {}
    for period in ("hourly", "daily", "weekly", "monthly"):
        d = f"/etc/cron.{period}"
        if os.path.isdir(d):
            periodic[period] = sorted(os.listdir(d))
    # systemd timers
    timers = []
    if which("systemctl"):
        for line in run(["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"])[1].splitlines():
            # NEXT LEFT LAST PASSED UNIT ACTIVATES  （时间字段含空格，按 .timer 定位）
            m = re.search(r"(\S+\.timer)\s+(\S+)\s*$", line)
            if m:
                head = line[:m.start()].strip()
                timers.append({"unit": m.group(1), "activates": m.group(2), "next_last": head})
    # at 任务
    at_jobs = run(["atq"])[1].splitlines() if which("atq") else []
    unreadable = [p for p in ("/var/spool/cron/crontabs", "/var/spool/cron") if os.path.isdir(p) and not os.access(p, os.R_OK)]
    return {"cron": jobs, "periodic": periodic, "timers": timers, "at": at_jobs,
            "note": f"无权读取 {unreadable}，用户 crontab 需 root" if unreadable else ""}


def cron_history(lines: int = 200) -> list[str]:
    if which("journalctl"):
        for unit in ("cron", "crond"):
            out = run(["journalctl", "-u", unit, "--no-pager", "-o", "short-iso", "-n", str(lines)], timeout=30)[1]
            if out.strip() and "No entries" not in out:
                return out.splitlines()
    for f in ("/var/log/cron", "/var/log/cron.log", "/var/log/syslog"):
        if os.path.isfile(f):
            return [l for l in read_lines(f) if "CRON" in l or "crond" in l][-lines:]
    return []


# ---------------------------------------------------------------- 开机启动项
def startup_items() -> dict:
    res = {"systemd_enabled": [], "sysv": [], "rc_local": "", "user_units": [], "profile_scripts": [], "modules": []}
    if which("systemctl"):
        for line in run(["systemctl", "list-unit-files", "--state=enabled", "--no-pager", "--no-legend", "--plain"])[1].splitlines():
            p = line.split()
            if p:
                res["systemd_enabled"].append(p[0])
    for f in sorted(glob.glob("/etc/rc[2-5].d/S*")):
        res["sysv"].append(os.path.basename(f))
    for f in ("/etc/rc.local", "/etc/rc.d/rc.local"):
        if os.path.isfile(f):
            res["rc_local"] = read_text(f)
            break
    from ..utils import home_dirs
    for user, home in home_dirs():
        for f in glob.glob(os.path.join(home, ".config/systemd/user/*.service")):
            res["user_units"].append({"user": user, "unit": f})
        for f in (".bashrc", ".profile", ".bash_profile", ".zshrc"):
            p = os.path.join(home, f)
            if os.path.isfile(p):
                suspicious = [l for l in read_lines(p) if re.search(r"(curl|wget).*\|\s*(ba)?sh|nohup|/tmp/|base64 -d", l)]
                if suspicious:
                    res["profile_scripts"].append({"user": user, "file": p, "suspicious": suspicious})
    res["profile_d"] = sorted(os.listdir("/etc/profile.d")) if os.path.isdir("/etc/profile.d") else []
    for f in glob.glob("/etc/modules-load.d/*.conf") + ["/etc/modules"]:
        if os.path.isfile(f):
            res["modules"] += [l.strip() for l in read_lines(f) if l.strip() and not l.startswith("#")]
    return res


def summary() -> dict:
    svc = services()
    failed = [s["unit"] for s in svc if s["active"] == "failed"]
    procs = list_processes(limit=5, interval=0.3)
    return {"services": len(svc), "failed_services": failed, "processes": procs["total"],
            "zombies": [z["pid"] for z in procs["zombies"]], "load": procs["load"],
            "top_cpu": [(p["name"], p["cpu"]) for p in procs["processes"]], "cron_jobs": len(cron_jobs()["cron"])}
