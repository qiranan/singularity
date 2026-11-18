"""模块7：日志 —— /var/log 浏览与搜索、journal 查询、logrotate 检查、异常日志聚合。"""
from __future__ import annotations

import collections
import glob
import os
import re
import shutil
import time

from ..utils import run, which, read_lines, tail_file, human_bytes, human_time, recent_log_lines

LOG_DIR = "/var/log"
LEVEL_PATTERNS = {
    "critical": re.compile(r"\b(CRIT(?:ICAL)?|EMERG|ALERT|FATAL|PANIC)\b", re.I),
    "error": re.compile(r"\b(ERR(?:OR)?|FAIL(?:ED|URE)?|EXCEPTION|TRACEBACK|SEGFAULT|DENIED)\b", re.I),
    "warning": re.compile(r"\b(WARN(?:ING)?)\b", re.I),
    "info": re.compile(r"\b(INFO|NOTICE)\b", re.I),
    "debug": re.compile(r"\b(DEBUG|TRACE)\b", re.I),
}
LEVEL_ORDER = ["debug", "info", "warning", "error", "critical"]


def _level_of(line: str) -> str:
    for lvl in ("critical", "error", "warning", "info", "debug"):
        if LEVEL_PATTERNS[lvl].search(line):
            return lvl
    return "info"


# ---------------------------------------------------------------- 文件清单
def list_logs(root: str = LOG_DIR, top: int = 20) -> dict:
    files, total = [], 0
    for cur, dirs, names in os.walk(root):
        for n in names:
            p = os.path.join(cur, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not os.path.isfile(p):
                continue
            rotated = bool(re.search(r"\.(\d+|gz|xz|bz2|old|bak)$|-\d{8}", n))
            files.append({"path": p, "size": st.st_size, "size_human": human_bytes(st.st_size),
                          "mtime": human_time(st.st_mtime), "rotated": rotated, "readable": os.access(p, os.R_OK)})
            total += st.st_size
    files.sort(key=lambda f: f["size"], reverse=True)
    du = shutil.disk_usage(root)
    pct = du.used / du.total * 100
    alerts = []
    if pct > 90:
        alerts.append({"level": "high", "msg": f"{root} 所在分区已用 {pct:.0f}%"})
    if total > du.total * 0.2:
        alerts.append({"level": "medium", "msg": f"日志占用 {human_bytes(total)}，超过分区 20%"})
    for f in files[:5]:
        if f["size"] > 1 << 30 and not f["rotated"]:
            alerts.append({"level": "medium", "msg": f"{f['path']} 超过 1GB 且未轮转"})
    active = [f for f in files if not f["rotated"]]
    return {"total_size": total, "total_human": human_bytes(total), "count": len(files), "active_count": len(active),
            "largest": files[:top], "disk_used_pct": round(pct, 1), "disk_free": human_bytes(du.free),
            "journal_size": _journal_usage(), "alerts": alerts}


def _journal_usage() -> str:
    if which("journalctl"):
        out = run(["journalctl", "--disk-usage"])[1]
        m = re.search(r"take up ([\d.]+\s?[KMGT]?i?B)", out)
        return m.group(1) if m else out.strip()
    return "-"


# ---------------------------------------------------------------- 读取与搜索
def read_log(path: str, lines: int = 200, grep: str | None = None, level: str | None = None,
             ignore_case: bool = True, context: int = 0) -> dict:
    if lines <= 0 or context < 0:
        return {"error": "lines must be positive and context must be non-negative"}
    real = os.path.realpath(path)
    if not any(real == root or real.startswith(root + os.sep)
               for root in ("/var/log", "/opt", "/srv", "/home", "/tmp", "/data", "/app")):
        return {"error": "出于安全考虑，只允许读取 /var/log /opt /srv /home /data /app /tmp 下的文件"}
    if not os.path.isfile(real):
        return {"error": "file not found"}
    if not os.access(real, os.R_OK):
        return {"error": "permission denied（需 root 或 adm 组）"}
    # 有过滤条件时多扫一些行
    try:
        pat = re.compile(grep, re.I if ignore_case else 0) if grep else None
    except re.error as exc:
        return {"error": f"invalid regular expression: {exc}"}
    raw = tail_file(real, lines if not (grep or level) else max(lines * 50, 5000))
    min_idx = LEVEL_ORDER.index(level) if level in LEVEL_ORDER else -1
    out, counts = [], collections.Counter()
    for i, l in enumerate(raw):
        lv = _level_of(l)
        counts[lv] += 1
        if pat and not pat.search(l):
            continue
        if min_idx >= 0 and LEVEL_ORDER.index(lv) < min_idx:
            continue
        if context and pat:
            block = raw[max(0, i - context):i + context + 1]
            out.append({"level": lv, "line": l, "context": block})
        else:
            out.append({"level": lv, "line": l})
    return {"path": real, "size": os.path.getsize(real), "scanned": len(raw), "matched": len(out),
            "lines": out[-lines:], "level_counts": dict(counts)}


def search_logs(pattern: str, root: str = LOG_DIR, max_files: int = 60, max_hits: int = 500) -> dict:
    """跨文件 grep（只搜未轮转的文本日志）。"""
    hits, scanned = [], 0
    try:
        pat = re.compile(pattern, re.I)
    except re.error as exc:
        return {"error": f"invalid regular expression: {exc}", "hits": [], "files_scanned": 0, "truncated": False}
    for cur, dirs, names in os.walk(root):
        for n in sorted(names):
            p = os.path.join(cur, n)
            if re.search(r"\.(gz|xz|bz2|\d+|journal|bin)$", n) or not os.access(p, os.R_OK) or not os.path.isfile(p):
                continue
            if scanned >= max_files:
                break
            scanned += 1
            for l in tail_file(p, 20000):
                if pat.search(l):
                    hits.append({"file": p, "line": l[:500]})
                    if len(hits) >= max_hits:
                        return {"hits": hits, "files_scanned": scanned, "truncated": True}
    return {"hits": hits, "files_scanned": scanned, "truncated": False}


def journal(unit: str | None = None, since: str = "1 hour ago", priority: str | None = None, lines: int = 200,
            grep: str | None = None, kernel: bool = False, boot: bool = False) -> dict:
    if not which("journalctl"):
        return {"error": "journalctl 不可用", "lines": []}
    cmd = ["journalctl", "--no-pager", "-o", "short-iso", "-n", str(lines)]
    if unit:
        cmd += ["-u", unit]
    if since:
        cmd += ["--since", since]
    if priority:
        cmd += ["-p", priority]
    if grep:
        cmd += ["-g", grep]
    if kernel:
        cmd.append("-k")
    if boot:
        cmd.append("-b")
    rc, out, err = run(cmd, timeout=60)
    rows = [{"level": _level_of(l), "line": l} for l in out.splitlines()]
    return {"command": " ".join(cmd), "lines": rows, "error": err.strip() if rc else ""}


# ---------------------------------------------------------------- logrotate
def _parse_logrotate(path: str) -> list[dict]:
    """解析 logrotate 配置：返回每个块的 {files:[], options:{}}。"""
    blocks, globals_, cur_files, cur_opts, depth = [], {}, [], {}, 0
    for raw in read_lines(path):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.endswith("{"):
            cur_files = line[:-1].split()
            cur_opts = {}
            depth = 1
            continue
        if line == "}":
            blocks.append({"files": cur_files, "options": cur_opts, "config": path})
            depth = 0
            continue
        parts = line.split(None, 1)
        target = cur_opts if depth else globals_
        target[parts[0]] = parts[1] if len(parts) > 1 else True
    return blocks, globals_


def logrotate_check() -> dict:
    blocks, globals_ = [], {}
    files = ["/etc/logrotate.conf"] + sorted(glob.glob("/etc/logrotate.d/*"))
    for f in files:
        if os.path.isfile(f):
            b, g = _parse_logrotate(f)
            blocks += b
            globals_.update(g)
    # 哪些活跃日志文件没有被任何规则覆盖
    covered = set()
    for b in blocks:
        for pat in b["files"]:
            covered.update(os.path.realpath(p) for p in glob.glob(pat))
    uncovered = []
    for p in glob.glob("/var/log/**/*", recursive=True):
        if os.path.isfile(p) and not re.search(r"\.(\d+|gz|xz|bz2|journal|old)$|-\d{8}", p) and os.path.realpath(p) not in covered:
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            if size > 10 * 1024 * 1024 and "/journal/" not in p:
                uncovered.append({"path": p, "size_human": human_bytes(size)})
    uncovered.sort(key=lambda x: x["path"])
    # 上次执行状态
    status, stale = {}, []
    for sf in ("/var/lib/logrotate/status", "/var/lib/logrotate.status"):
        if os.path.isfile(sf):
            for line in read_lines(sf)[1:]:
                m = re.match(r'^"?([^"]+)"?\s+(\S+)', line)
                if m:
                    status[m.group(1)] = m.group(2)
            break
    last_run = max(status.values()) if status else None
    if last_run:
        try:
            if time.time() - time.mktime(time.strptime(last_run[:10], "%Y-%m-%d")) > 3 * 86400:
                stale.append({"level": "medium", "msg": f"logrotate 上次运行于 {last_run}，超过 3 天"})
        except ValueError:
            pass
    issues = list(stale)
    for b in blocks:
        o = b["options"]
        if not any(k in o or k in globals_ for k in ("rotate", "maxage")):
            issues.append({"level": "low", "msg": f"{b['files']} 未设置 rotate/maxage，可能无限保留", "config": b["config"]})
        if "compress" not in o and "compress" not in globals_:
            issues.append({"level": "info", "msg": f"{b['files']} 未压缩", "config": b["config"]})
    for u in uncovered:
        issues.append({"level": "medium", "msg": f"{u['path']} ({u['size_human']}) 未被 logrotate 覆盖"})
    journald = {}
    for f in ["/etc/systemd/journald.conf"] + glob.glob("/etc/systemd/journald.conf.d/*.conf"):
        for line in read_lines(f):
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                journald[k.strip()] = v.strip()
    return {"configs": files, "blocks": len(blocks), "globals": globals_, "last_run": last_run,
            "uncovered_large_files": uncovered, "issues": issues, "journald": journald,
            "timer": _logrotate_timer()}


def _logrotate_timer() -> str:
    if which("systemctl"):
        out = run(["systemctl", "list-timers", "logrotate.timer", "--no-pager", "--no-legend"])[1].strip()
        if out:
            return out
    return "cron: /etc/cron.daily/logrotate" if os.path.exists("/etc/cron.daily/logrotate") else "未找到定时触发"


# ---------------------------------------------------------------- 异常聚合
ANOMALY_RULES = [
    ("oom", "critical", r"Out of memory|oom-killer|Killed process \d+", "内存耗尽，OOM Killer 杀进程"),
    ("kernel_bug", "critical", r"kernel BUG|Kernel panic|Call Trace:|general protection fault", "内核错误/崩溃"),
    ("segfault", "error", r"segfault at|SIGSEGV|core dumped", "进程段错误"),
    ("io_error", "critical", r"I/O error|EXT4-fs error|XFS .*corrupt|Buffer I/O error|blk_update_request", "磁盘 IO 错误"),
    ("disk_full", "error", r"No space left on device|write error: disk full", "磁盘空间不足"),
    ("service_failed", "error", r"Failed with result|entered failed state|Start request repeated too quickly", "服务启动失败"),
    ("service_restart", "warning", r"Scheduled restart job|Main process exited, code=(killed|exited)", "服务崩溃/自动重启"),
    ("auth_failure", "warning", r"authentication failure|Failed password|Invalid user", "认证失败"),
    ("sudo", "info", r"sudo:.*COMMAND=", "sudo 使用记录"),
    ("network", "warning", r"link (down|is not ready)|NIC Link is Down|carrier lost|DHCP.*fail", "网络链路问题"),
    ("hardware", "error", r"Hardware Error|MCE|temperature above threshold|SMART error|Uncorrected", "硬件/温度告警"),
    ("time", "warning", r"time (jump|reset)|clock.*(skew|step)|chronyd.*(Can't synchronise)", "时钟异常"),
    ("docker", "warning", r"dockerd\[\d+\]:.*level=(error|warning)", "docker 告警"),
    ("nginx_apache", "error", r"nginx.*\[(emerg|crit|error)\]|apache.*\[error\]|upstream timed out|502 Bad Gateway", "Web 服务器错误"),
    ("db", "error", r"(mysql|mariadb|postgres).*\b(ERROR|FATAL|crash|Aborted connection)", "数据库错误"),
]


def anomalies(hours: int = 24, max_samples: int = 5) -> dict:
    """聚合近 N 小时内的异常日志。"""
    if hours <= 0:
        raise ValueError("hours must be positive")
    text = ""
    sources, unknown_time_lines = [], 0
    journal_ok = False
    if which("journalctl"):
        rc, text, _ = run(["journalctl", "--no-pager", "-o", "short-iso", "--since", f"{hours} hours ago", "-p", "warning"], timeout=120)
        journal_ok = rc == 0
        if journal_ok:
            sources.append("journalctl -p warning")
        else:
            text = ""
        rc2, ktext, _ = run(["journalctl", "--no-pager", "-k", "-o", "short-iso", "--since", f"{hours} hours ago"], timeout=60)
        if rc2 == 0:
            text += "\n" + ktext
            sources.append("journalctl -k")
    if not journal_ok:
        for f in ("/var/log/syslog", "/var/log/messages", "/var/log/kern.log", "/var/log/auth.log", "/var/log/secure"):
            if os.path.isfile(f) and os.access(f, os.R_OK):
                recent, unknown = recent_log_lines(tail_file(f, 50000), hours)
                text += "\n".join(recent) + "\n"
                unknown_time_lines += unknown
                sources.append(f)
    compiled = [(k, lvl, re.compile(p, re.I), desc) for k, lvl, p, desc in ANOMALY_RULES]
    groups = {k: {"key": k, "level": lvl, "description": desc, "count": 0, "samples": [], "units": collections.Counter()}
              for k, lvl, _, desc in ANOMALY_RULES}
    by_unit = collections.Counter()
    for line in text.splitlines():
        for k, lvl, pat, _ in compiled:
            if pat.search(line):
                g = groups[k]
                g["count"] += 1
                m = re.search(r"\s(\S+?)\[\d+\]:|\s([\w.-]+):\s", line)
                unit = (m.group(1) or m.group(2)) if m else "?"
                g["units"][unit] += 1
                by_unit[unit] += 1
                if len(g["samples"]) < max_samples:
                    g["samples"].append(line[:300])
                break
    found = [dict(g, units=g["units"].most_common(5)) for g in groups.values() if g["count"]]
    found.sort(key=lambda g: (LEVEL_ORDER.index(g["level"]) if g["level"] in LEVEL_ORDER else 0, g["count"]), reverse=True)
    # 失败的 systemd 单元
    failed_units = []
    if which("systemctl"):
        for line in run(["systemctl", "--failed", "--no-pager", "--no-legend", "--plain"])[1].splitlines():
            p = line.split()
            if p:
                failed_units.append(p[0])
    # 频繁重启的服务
    restarts = []
    if which("systemctl"):
        out = run(["systemctl", "show", "*", "--property=Id,NRestarts", "--no-pager"], timeout=30)[1]
        cur = {}
        for line in out.splitlines() + [""]:
            if line.startswith("Id="):
                cur["id"] = line[3:]
            elif line.startswith("NRestarts="):
                cur["n"] = int(line[10:] or 0)
            elif not line and cur.get("n", 0) >= 3:
                restarts.append({"unit": cur["id"], "restarts": cur["n"]})
                cur = {}
            elif not line:
                cur = {}
    return {"window_hours": hours, "sources": sources, "unknown_time_lines": unknown_time_lines,
            "groups": found, "noisy_units": by_unit.most_common(10),
            "failed_units": failed_units, "frequent_restarts": sorted(restarts, key=lambda r: -r["restarts"])[:10],
            "dmesg_tail": run(["dmesg", "-T", "--level=err,crit,alert,emerg"], timeout=10)[1].splitlines()[-20:]}


def summary() -> dict:
    ls = list_logs(top=3)
    an = anomalies(hours=24, max_samples=1)
    return {"log_total": ls["total_human"], "disk_used_pct": ls["disk_used_pct"], "journal": ls["journal_size"],
            "alerts": ls["alerts"], "anomaly_groups": [(g["key"], g["count"]) for g in an["groups"]],
            "failed_units": an["failed_units"]}
