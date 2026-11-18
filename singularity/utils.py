"""通用工具：执行命令、读文件、格式化、审计日志。"""
from __future__ import annotations

import datetime as _dt
from collections import deque
import json
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Iterable

DATA_DIR = Path(os.environ.get("SINGULARITY_HOME", os.path.expanduser("~/.singularity")))
_AUDIT_LOCK = threading.Lock()
AUDIT_MAX_BYTES = 1024 * 1024


def data_dir() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR


def which(name: str) -> str | None:
    return shutil.which(name)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def run(cmd: list[str] | str, timeout: int = 20, shell: bool = False, env: dict | None = None):
    """执行命令，返回 (returncode, stdout, stderr)。命令不存在返回 127，超时返回 124。"""
    if not shell:
        if which(cmd[0]) is None and not os.path.exists(cmd[0]):
            return 127, "", f"command not found: {cmd[0]}"
    merged_env = dict(os.environ)
    # 解析器依赖英文列名，不能继承宿主机的本地化输出。
    merged_env.update(LANG="C", LC_ALL="C")
    if env:
        merged_env.update(env)
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, shell=shell,
            errors="replace", env=merged_env,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except OSError as e:
        return 1, "", str(e)


def read_text(path: str | Path, default: str = "", max_bytes: int | None = None) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(max_bytes) if max_bytes else f.read()
    except (OSError, PermissionError):
        return default


def read_lines(path: str | Path) -> list[str]:
    return read_text(path).splitlines()


def human_bytes(n: float | int | None) -> str:
    if n is None:
        return "-"
    n = float(n)
    for unit in ("B", "K", "M", "G", "T"):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}P"


def human_time(ts: float | int | None) -> str:
    if not ts:
        return "-"
    return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def now_iso() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")


def mode_str(mode: int) -> str:
    return oct(mode & 0o7777)


def tail_file(path: str | Path, lines: int = 200, max_scan: int = 8 * 1024 * 1024) -> list[str]:
    """从文件尾部读取最后 N 行（支持 .gz）。"""
    if lines < 0:
        raise ValueError("lines must be non-negative")
    if lines == 0:
        return []
    p = Path(path)
    try:
        if p.suffix == ".gz":
            import gzip
            with gzip.open(p, "rt", errors="replace") as f:
                return [line.rstrip("\r\n") for line in deque(f, maxlen=lines)]
        size = p.stat().st_size
        with open(p, "rb") as f:
            f.seek(max(0, size - max_scan))
            data = f.read()
        return data.decode("utf-8", errors="replace").splitlines()[-lines:]
    except (OSError, PermissionError):
        return []


def audit(action: str, detail: dict | str, actor: str = "cli") -> None:
    """记录审计并轮转；失败交由调用方反馈，避免误报审计成功。"""
    line = json.dumps({"time": now_iso(), "actor": actor, "action": action, "detail": detail},
                      ensure_ascii=False) + "\n"
    with _AUDIT_LOCK:
        directory = data_dir()
        with open(directory / "audit.lock", "a") as lock:
            try:
                import fcntl
            except ImportError:  # Windows 上的解析器测试只需线程锁
                fcntl = None
            if fcntl is not None:
                fcntl.flock(lock, fcntl.LOCK_EX)
            path = directory / "audit.log"
            if path.exists() and path.stat().st_size + len(line.encode("utf-8")) > AUDIT_MAX_BYTES:
                for index in range(3, 0, -1):
                    source = directory / (f"audit.log.{index - 1}" if index > 1 else "audit.log")
                    if source.exists():
                        os.replace(source, directory / f"audit.log.{index}")
            with open(path, "a", encoding="utf-8") as output:
                output.write(line)


def audit_result(action: str, result: dict, actor: str = "cli", detail=None) -> dict:
    """保留操作结果，单独报告审计失败；调用者据此避免盲目重试写操作。"""
    try:
        audit(action, result if detail is None else detail, actor)
    except OSError as exc:
        result["audit_error"] = f"审计记录失败: {exc}；请先核对操作结果再决定是否重试"
    return result


def log_timestamp(line: str, now: _dt.datetime) -> _dt.datetime | None:
    """识别 ISO 与传统 syslog 时间；syslog 缺少年份时处理跨年。"""
    match = re.match(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?", line)
    if match:
        try:
            stamp = _dt.datetime.fromisoformat(match.group().replace("Z", "+00:00"))
            return stamp.replace(tzinfo=now.tzinfo) if stamp.tzinfo is None else stamp
        except ValueError:
            return None
    match = re.match(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)", line)
    if match:
        months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
        try:
            month = months.index(match[1]) + 1
            day, hour, minute, second = map(int, match.groups()[1:])
            for year in (now.year, now.year - 1):
                try:
                    stamp = _dt.datetime(year, month, day, hour, minute, second, tzinfo=now.tzinfo)
                except ValueError:
                    continue
                if stamp <= now + _dt.timedelta(minutes=5):
                    return stamp
        except ValueError:
            pass
    return None


def recent_log_lines(lines: Iterable[str], hours: int, now: _dt.datetime | None = None) -> tuple[list[str], int]:
    """过滤文件日志窗口，保留有时间戳记录的续行，返回无法定时的行数。"""
    if hours <= 0:
        raise ValueError("hours must be positive")
    now = now or _dt.datetime.now().astimezone()
    cutoff = now.timestamp() - hours * 3600
    result, unknown, previous = [], 0, None
    for line in lines:
        stamp = log_timestamp(line, now)
        if stamp is not None:
            previous = stamp
        elif not line[:1].isspace():
            previous = None
        if previous is None:
            unknown += 1
        elif cutoff <= previous.timestamp() <= now.timestamp():
            result.append(line)
    return result, unknown


def uid_to_name(uid: int) -> str:
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return str(uid)


def pid_user(pid: int) -> str:
    try:
        return uid_to_name(os.stat(f"/proc/{pid}").st_uid)
    except OSError:
        return "?"


def pid_name(pid: int) -> str:
    return read_text(f"/proc/{pid}/comm").strip() or "?"


def pid_cmdline(pid: int) -> str:
    raw = read_text(f"/proc/{pid}/cmdline")
    return raw.replace("\x00", " ").strip() or pid_name(pid)


def home_dirs() -> list[tuple[str, str]]:
    """返回 (用户名, home目录) 列表，只含存在的目录。"""
    out = []
    for line in read_lines("/etc/passwd"):
        parts = line.split(":")
        if len(parts) >= 7 and os.path.isdir(parts[5]) and parts[5] not in ("/", "/nonexistent"):
            out.append((parts[0], parts[5]))
    return out


