"""模块1：账号与权限 —— 用户清单、sudo 审计、SSH 密钥、登录审计、风险检查、文件权限扫描。"""
from __future__ import annotations

import base64
import collections
import datetime as dt
import glob
import hashlib
import os
import re
import stat
import time

from ..utils import read_lines, run, which, mode_str, is_root, tail_file, recent_log_lines, log_timestamp

NOLOGIN_SHELLS = {"/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false", "/bin/sync"}


# ---------------------------------------------------------------- 用户清单
def _parse_shadow() -> dict[str, dict]:
    """解析 /etc/shadow（需要 root），返回 {user: info}。"""
    out = {}
    for line in read_lines("/etc/shadow"):
        p = line.split(":")
        if len(p) < 8:
            continue
        pw = p[1]
        if pw == "":
            status = "empty"          # 空密码：无需密码即可登录（高危）
        elif pw.startswith("!") or pw.startswith("*"):
            status = "locked"
        else:
            status = "set"
        last_change = int(p[2]) if p[2].isdigit() else None
        max_days = int(p[4]) if p[4].isdigit() else None
        expire = int(p[7]) if p[7].isdigit() else None
        today = int(time.time() // 86400)
        pw_expired = bool(last_change is not None and max_days not in (None, 99999)
                          and last_change + max_days < today)
        out[p[0]] = {
            "password": status,
            "last_change": (dt.date(1970, 1, 1) + dt.timedelta(days=last_change)).isoformat() if last_change else None,
            "max_days": max_days,
            "password_expired": pw_expired,
            "account_expired": bool(expire and expire < today),
        }
    return out


def _groups_of() -> tuple[dict[str, str], dict[str, list[str]]]:
    """返回 (gid->组名, 用户->[附加组])。"""
    gid_name, member_groups = {}, collections.defaultdict(list)
    for line in read_lines("/etc/group"):
        p = line.split(":")
        if len(p) < 4:
            continue
        gid_name[p[2]] = p[0]
        for m in filter(None, p[3].split(",")):
            member_groups[m].append(p[0])
    return gid_name, member_groups


# 组名 -> (权限等级, 说明)。等级从高到低见 PRIV_ORDER。
GROUP_PRIVILEGES = {
    "root": ("root", "超级用户组"),
    "sudo": ("root", "可通过 sudo 以 root 执行任意命令（Debian/Ubuntu）"),
    "wheel": ("root", "可通过 sudo / su 提权（RHEL/CentOS/Arch/Alpine）"),
    "admin": ("root", "旧版 Ubuntu 管理组，sudo 任意命令"),
    "docker": ("root-equiv", "可操作 docker daemon，能挂载宿主机根目录，等同 root"),
    "lxd": ("root-equiv", "可创建特权容器，等同 root"),
    "lxc": ("root-equiv", "可创建特权容器，等同 root"),
    "disk": ("root-equiv", "可直接读写块设备 /dev/sd*，等同 root"),
    "libvirt": ("root-equiv", "可管理虚拟机并挂载宿主磁盘，接近 root"),
    "libvirtd": ("root-equiv", "可管理虚拟机并挂载宿主磁盘，接近 root"),
    "shadow": ("high", "可读取 /etc/shadow 密码哈希"),
    "adm": ("medium", "可读取 /var/log 系统日志"),
    "systemd-journal": ("medium", "可读取全部 journal 日志"),
    "staff": ("medium", "可写 /usr/local 与 /home"),
    "ssh": ("medium", "sshd AllowGroups 启用时允许 SSH 登录"),
    "sshusers": ("medium", "sshd AllowGroups 启用时允许 SSH 登录"),
    "lpadmin": ("medium", "可管理打印机（CUPS）"),
    "sambashare": ("medium", "可创建 Samba 共享"),
    "netdev": ("medium", "可管理网络连接（NetworkManager）"),
    "kvm": ("medium", "可访问 /dev/kvm 使用硬件虚拟化"),
    "input": ("medium", "可读取输入设备（可记录键盘）"),
    "video": ("device", "访问显卡 / 摄像头设备"),
    "render": ("device", "访问 GPU 渲染节点"),
    "audio": ("device", "访问声卡"),
    "plugdev": ("device", "挂载可移动存储设备"),
    "dialout": ("device", "访问串口 / 调制解调器"),
    "cdrom": ("device", "访问光驱"),
    "floppy": ("device", "访问软驱"),
    "tape": ("device", "访问磁带设备"),
    "tty": ("device", "访问终端设备"),
    "bluetooth": ("device", "使用蓝牙"),
    "scanner": ("device", "使用扫描仪"),
    "www-data": ("service", "Web 服务运行组"),
    "nginx": ("service", "Nginx 运行组"),
    "apache": ("service", "Apache 运行组"),
    "mysql": ("service", "MySQL/MariaDB 运行组，可读数据库文件"),
    "postgres": ("service", "PostgreSQL 运行组，可读数据库文件"),
    "redis": ("service", "Redis 运行组"),
    "mongodb": ("service", "MongoDB 运行组"),
    "users": ("normal", "普通用户组"),
    "nogroup": ("normal", "无特权占位组"),
    "nobody": ("normal", "无特权占位组"),
}
PRIV_ORDER = ["root", "root-equiv", "high", "medium", "device", "service", "normal", "unknown"]
PRIV_LABEL = {"root": "ROOT", "root-equiv": "ROOT≈", "high": "高", "medium": "中", "device": "设备",
              "service": "服务", "normal": "普通", "unknown": "未知"}


def _group_privilege(name: str, gid: int | None = None) -> tuple[str, str]:
    if name in GROUP_PRIVILEGES:
        return GROUP_PRIVILEGES[name]
    if gid == 0:
        return "root", "GID 0"
    if gid is not None and gid < 1000:
        return "service", "系统组"
    return "normal", "用户私有组或自定义组"


def _sudo_rules_for(user: str, groups: list[str], rules: list[dict]) -> list[dict]:
    """找出作用于该用户的 sudo 规则（直接指定用户或通过 %组）。"""
    hits = []
    for r in rules:
        who = r["who"]
        if who == user or who == "ALL":
            hits.append(dict(r, via="user"))
        elif who.startswith("%") and who[1:] in groups:
            hits.append(dict(r, via=who))
    return hits


def _user_privileges(user: dict, sudo_rules: list[dict]) -> list[dict]:
    """汇总一个用户的有效权限来源，按等级排序。"""
    privs = []
    if user["uid"] == 0:
        privs.append({"level": "root", "source": "uid=0", "desc": "超级用户"})
    for g in user["groups"]:
        lvl, desc = _group_privilege(g, user["gid"] if g == user["groups"][0] else None)
        if lvl in ("normal",) and g == user["user"]:
            continue  # 同名私有组不值一提
        if lvl != "normal" or g in GROUP_PRIVILEGES:
            privs.append({"level": lvl, "source": f"组 {g}", "desc": desc})
    for r in sudo_rules:
        if "ALL" in r["commands"]:
            desc = "sudo 任意命令" + ("（免密）" if r["nopasswd"] else "")
            lvl = "root"
        else:
            desc = "sudo 执行 " + ", ".join(r["commands"]) + ("（免密）" if r["nopasswd"] else "")
            lvl = "high"
        src = f"sudoers {r['via']}" if r["via"] != "user" else "sudoers"
        privs.append({"level": lvl, "source": src, "desc": desc, "rule": r["raw"]})
    privs.sort(key=lambda p: PRIV_ORDER.index(p["level"]))
    return privs


def _max_level(privs: list[dict]) -> str:
    return min((p["level"] for p in privs), key=PRIV_ORDER.index, default="normal")


def list_users(include_system: bool = True) -> list[dict]:
    shadow = _parse_shadow()
    gid_name, member_groups = _groups_of()
    rules = sudo_audit(include_groups=False)["rules"]
    users = []
    for line in read_lines("/etc/passwd"):
        p = line.split(":")
        if len(p) < 7:
            continue
        name, uid, gid, home, shell = p[0], int(p[2]), int(p[3]), p[5], p[6]
        is_system = uid < 1000 and name != "root"
        if is_system and not include_system:
            continue
        primary = gid_name.get(str(gid), str(gid))
        groups = [primary] + [g for g in member_groups.get(name, []) if g != primary]
        s = shadow.get(name, {})
        u = {
            "user": name, "uid": uid, "gid": gid, "home": home, "shell": shell,
            "can_login": shell not in NOLOGIN_SHELLS,
            "is_system": is_system,
            "groups": groups,
            "primary_group": primary,
            "is_admin": bool({"sudo", "wheel", "admin", "root"} & set(groups)),
            "password": s.get("password", "unknown"),
            "password_last_change": s.get("last_change"),
            "password_expired": s.get("password_expired"),
            "account_expired": s.get("account_expired"),
            "home_exists": os.path.isdir(home),
        }
        u["sudo_rules"] = _sudo_rules_for(name, groups, rules)
        u["privileges"] = _user_privileges(u, u["sudo_rules"])
        u["max_level"] = _max_level(u["privileges"])
        users.append(u)
    users.sort(key=lambda x: (PRIV_ORDER.index(x["max_level"]), x["is_system"], x["uid"]))
    return users


def groups_view(include_empty: bool = False) -> list[dict]:
    """以组为中心：每个组的成员（主组/附加组）、权限等级、说明、相关 sudo 规则。"""
    gid_name, member_groups = _groups_of()
    rules = sudo_audit(include_groups=False)["rules"]
    primary_members = collections.defaultdict(list)
    for line in read_lines("/etc/passwd"):
        p = line.split(":")
        if len(p) >= 7:
            primary_members[gid_name.get(p[3], p[3])].append(p[0])
    groups = []
    for gid_s, name in gid_name.items():
        gid = int(gid_s) if gid_s.isdigit() else -1
        members = [{"user": u, "primary": True} for u in primary_members.get(name, [])]
        members += [{"user": u, "primary": False} for u, gs in member_groups.items() if name in gs
                    and u not in primary_members.get(name, [])]
        lvl, desc = _group_privilege(name, gid)
        sudo = [r for r in rules if r["who"] == f"%{name}"]
        if sudo and lvl not in ("root",):
            lvl = "root" if any("ALL" in r["commands"] for r in sudo) else "high"
            desc = desc + "；" if desc else ""
            desc += "sudoers 授予 " + ("任意命令" if lvl == "root" else "特定命令")
        if not members and not include_empty and lvl in ("normal", "service", "device"):
            continue
        groups.append({"group": name, "gid": gid, "level": lvl, "description": desc,
                       "members": sorted(members, key=lambda m: (not m["primary"], m["user"])),
                       "member_count": len(members), "sudo_rules": [r["raw"] for r in sudo],
                       "is_private": len(members) == 1 and members[0]["user"] == name and lvl == "normal"})
    groups.sort(key=lambda g: (PRIV_ORDER.index(g["level"]), -g["member_count"], g["gid"]))
    return groups


# ---------------------------------------------------------------- sudo 审计
def sudo_audit(include_groups: bool = True) -> dict:
    files = ["/etc/sudoers"] + sorted(glob.glob("/etc/sudoers.d/*"))
    rules, findings, unreadable = [], [], []
    for f in files:
        if not os.access(f, os.R_OK):
            unreadable.append(f)
            continue
        for ln, raw in enumerate(read_lines(f), 1):
            line = raw.split("#", 1)[0].strip() if not raw.startswith("#include") else ""
            if not line or line.startswith(("Defaults", "@include")):
                continue
            # 形如: user HOST=(RUNAS) [TAG:] CMD
            m = re.match(r"^(\S+)\s+(\S+?)\s*=\s*(?:\(([^)]*)\))?\s*(.*)$", line)
            if not m:
                continue
            who, host, runas, cmds = m.groups()
            nopasswd = "NOPASSWD:" in cmds
            cmd_list = [c.strip().replace("NOPASSWD:", "").replace("PASSWD:", "").strip() for c in cmds.split(",")]
            rule = {"file": f, "line": ln, "who": who, "host": host, "runas": runas or "root",
                    "nopasswd": nopasswd, "commands": cmd_list, "raw": line}
            rules.append(rule)
            if "ALL" in cmd_list and nopasswd:
                findings.append({"level": "high", "msg": f"{who} 免密可执行任何命令", "rule": line, "file": f})
            elif "ALL" in cmd_list and who not in ("root", "%sudo", "%wheel", "%admin"):
                findings.append({"level": "medium", "msg": f"{who} 可执行任何命令", "rule": line, "file": f})
            dangerous = [c for c in cmd_list if re.search(r"/(bash|sh|zsh|vi|vim|nano|less|more|python\d*|perl|find|awk|tee|env|su)$", c)]
            if dangerous:
                findings.append({"level": "high", "msg": f"{who} 可 sudo 执行可提权命令 {dangerous}", "rule": line, "file": f})
    # 组成员
    admin_members = {}
    if include_groups:
        _, member_groups = _groups_of()
        admin_members = {g: [u for u, gs in member_groups.items() if g in gs] for g in ("sudo", "wheel", "admin")}
    return {"rules": rules, "findings": findings, "admin_groups": admin_members,
            "unreadable_files": unreadable, "note": "" if is_root() else "非 root 运行，sudoers 可能不可读"}


# ---------------------------------------------------------------- SSH 密钥
def _fingerprint(key_line: str) -> tuple[str, str, str]:
    """返回 (类型, SHA256 指纹, 注释)。"""
    parts = key_line.split()
    opts = ""
    if parts and not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
        opts, parts = parts[0], parts[1:]
    if len(parts) < 2:
        return "?", "?", key_line[:40]
    ktype, b64 = parts[0], parts[1]
    comment = " ".join(parts[2:])
    try:
        digest = hashlib.sha256(base64.b64decode(b64)).digest()
        fp = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    except Exception:
        fp = "invalid"
    return ktype, fp, (comment + (f" [opts: {opts}]" if opts else "")).strip()


def ssh_keys() -> dict:
    keys, by_fp = [], collections.defaultdict(list)
    for line in read_lines("/etc/passwd"):
        p = line.split(":")
        if len(p) < 7:
            continue
        user, home = p[0], p[5]
        for name in ("authorized_keys", "authorized_keys2"):
            path = os.path.join(home, ".ssh", name)
            if not os.path.isfile(path):
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            for raw in read_lines(path):
                raw = raw.strip()
                if not raw or raw.startswith("#"):
                    continue
                ktype, fp, comment = _fingerprint(raw)
                weak = ktype == "ssh-rsa" and len(raw.split()[1]) < 300 if len(raw.split()) > 1 else False  # 粗略 <2048bit
                item = {"user": user, "file": path, "type": ktype, "fingerprint": fp, "comment": comment,
                        "weak": weak or ktype == "ssh-dss", "file_mode": mode_str(st.st_mode)}
                keys.append(item)
                by_fp[fp].append(user)
    dup = {fp: users for fp, users in by_fp.items() if len(users) > 1}
    for k in keys:
        k["shared_with"] = [u for u in dup.get(k["fingerprint"], []) if u != k["user"]]
    return {"keys": keys, "duplicates": dup, "total": len(keys)}


# ---------------------------------------------------------------- 登录审计
def _parse_last(output: str) -> list[dict]:
    rows = []
    for line in output.splitlines():
        if not line.strip() or line.startswith(("wtmp", "btmp")):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        user, tty = parts[0], parts[1]
        rest = parts[2:]
        ip = ""
        if rest and (re.match(r"^[\d.]+$|^[0-9a-fA-F:]+$", rest[0]) or "." in rest[0]) and not re.match(r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)$", rest[0]):
            ip = rest[0]
            rest = rest[1:]
        rows.append({"user": user, "tty": tty, "ip": ip, "when": " ".join(rest)})
    return rows


def login_audit(hours: int = 24, limit: int = 100) -> dict:
    if hours <= 0:
        raise ValueError("hours must be positive")
    # 当前在线
    online = []
    for line in run(["who"])[1].splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 3:
            online.append({"user": parts[0], "tty": parts[1], "since": " ".join(parts[2:4]),
                           "from": parts[4].strip("()") if len(parts) > 4 else ""})
    recent = _parse_last(run(["last", "-n", str(limit), "-w", "-F"])[1])
    failed = _parse_last(run(["lastb", "-n", str(limit), "-w", "-F"])[1])

    # sshd 失败登录统计（journal 或 auth.log）
    fail_by_ip, fail_by_user, accepted = collections.Counter(), collections.Counter(), []
    text, journal_ok, unknown_time_lines = "", False, 0
    sources = []
    if which("journalctl"):
        rc, text, _ = run(["journalctl", "--no-pager", "-o", "short-iso", "--since", f"{hours} hours ago",
                           "_COMM=sshd"], timeout=60)
        journal_ok = rc == 0
        if journal_ok:
            sources.append("journalctl _COMM=sshd")
        else:
            text = ""
    if not journal_ok:
        for f in ("/var/log/auth.log", "/var/log/secure"):
            if os.path.isfile(f):
                recent, unknown_time_lines = recent_log_lines(tail_file(f, 20000), hours)
                text = "\n".join(recent)
                sources.append(f)
                break
    for line in text.splitlines():
        m = re.search(r"Failed password for (invalid user )?(\S+) from (\S+)", line)
        if m:
            fail_by_user[m.group(2)] += 1
            fail_by_ip[m.group(3)] += 1
            continue
        m = re.search(r"Accepted (\S+) for (\S+) from (\S+)", line)
        if m:
            stamp = log_timestamp(line, dt.datetime.now().astimezone())
            accepted.append({"method": m.group(1), "user": m.group(2), "ip": m.group(3),
                             "line": stamp.strftime("%Y-%m-%dT%H:%M:%S") if stamp else line[:19]})

    alerts = []
    for ip, n in fail_by_ip.most_common():
        if n >= 10:
            alerts.append({"level": "high" if n >= 50 else "medium", "msg": f"{ip} 在 {hours}h 内失败登录 {n} 次（疑似暴力破解）"})
    for a in accepted:
        h = int(a["line"][11:13]) if len(a["line"]) >= 13 and a["line"][11:13].isdigit() else None
        if h is not None and (h < 7 or h >= 23):
            alerts.append({"level": "low", "msg": f"非工作时间登录: {a['user']} 来自 {a['ip']} @ {a['line']}"})
    if fail_by_user.get("root", 0) >= 5:
        alerts.append({"level": "medium", "msg": f"root 账号被尝试登录 {fail_by_user['root']} 次"})
    return {
        "online": online, "recent_logins": recent[:limit], "failed_logins": failed[:limit],
        "ssh_failed_by_ip": fail_by_ip.most_common(20), "ssh_failed_by_user": fail_by_user.most_common(20),
        "ssh_accepted": accepted[-50:], "alerts": alerts, "window_hours": hours,
        "sources": sources, "unknown_time_lines": unknown_time_lines,
    }


# ---------------------------------------------------------------- 风险检查
def risk_checks() -> list[dict]:
    issues = []
    users = list_users()
    shadow_readable = os.access("/etc/shadow", os.R_OK)
    uids = collections.Counter(u["uid"] for u in users)
    for u in users:
        if u["uid"] == 0 and u["user"] != "root":
            issues.append({"level": "critical", "user": u["user"], "msg": "UID 为 0 的非 root 账号（等同 root）"})
        if u["password"] == "empty":
            issues.append({"level": "critical", "user": u["user"], "msg": "空密码账号"})
        if u["can_login"] and u["is_system"] and u["user"] not in ("root", "sync"):
            issues.append({"level": "low", "user": u["user"], "msg": f"系统账号拥有可登录 shell {u['shell']}"})
        if u["password_expired"]:
            issues.append({"level": "medium", "user": u["user"], "msg": "密码已过期"})
        if u["account_expired"]:
            issues.append({"level": "low", "user": u["user"], "msg": "账号已过期但仍存在"})
        if uids[u["uid"]] > 1:
            issues.append({"level": "high", "user": u["user"], "msg": f"UID {u['uid']} 被多个账号共用"})
        if u["can_login"] and not u["is_system"] and not u["home_exists"]:
            issues.append({"level": "low", "user": u["user"], "msg": "家目录不存在"})
    # 长期未登录（lastlog）
    rc, out, _ = run(["lastlog", "-b", "90"])
    if rc == 0:
        for line in out.splitlines()[1:]:
            name = line.split()[0] if line.split() else ""
            u = next((x for x in users if x["user"] == name), None)
            if u and u["can_login"] and not u["is_system"] and "Never logged in" not in line:
                issues.append({"level": "low", "user": name, "msg": "超过 90 天未登录"})
    # sshd 配置
    sshd = _sshd_config()
    if sshd.get("permitrootlogin", "prohibit-password") in ("yes",):
        issues.append({"level": "high", "user": "root", "msg": "sshd 允许 root 密码登录 (PermitRootLogin yes)"})
    if sshd.get("passwordauthentication", "yes") == "yes":
        issues.append({"level": "medium", "user": "-", "msg": "sshd 允许密码登录，建议改为仅密钥"})
    if sshd.get("port", "22") == "22":
        issues.append({"level": "info", "user": "-", "msg": "sshd 使用默认 22 端口"})
    if not shadow_readable:
        issues.append({"level": "info", "user": "-", "msg": "/etc/shadow 不可读（非 root），密码相关检查被跳过"})
    return issues


def _sshd_config() -> dict:
    conf = {}
    files = ["/etc/ssh/sshd_config"] + sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf"))
    for f in files:
        for line in read_lines(f):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].lower() not in conf:  # 第一个生效
                conf[parts[0].lower()] = parts[1].strip().lower()
    return conf


# ---------------------------------------------------------------- 文件权限扫描
KNOWN_SUID = {
    "su", "sudo", "passwd", "chsh", "chfn", "gpasswd", "newgrp", "mount", "umount", "ping", "ping6",
    "fusermount", "fusermount3", "pkexec", "ssh-keysign", "chage", "expiry", "unix_chkpwd", "at",
    "crontab", "wall", "write", "dbus-daemon-launch-helper", "polkit-agent-helper-1", "ssh-agent",
    "mtr-packet", "traceroute6.iputils", "ntfs-3g", "snap-confine", "Xorg", "vmware-user-suid-wrapper",
    "pam_extrausers_chkpwd", "mlocate", "locate", "bsd-write", "utempter", "dotlockfile", "lockfile", "cockpit-session",
}

SENSITIVE = {
    "/etc/shadow": (0o640, "root"), "/etc/gshadow": (0o640, "root"), "/etc/passwd": (0o644, "root"),
    "/etc/group": (0o644, "root"), "/etc/sudoers": (0o440, "root"), "/etc/ssh/sshd_config": (0o644, "root"),
    "/etc/crontab": (0o644, "root"), "/root": (0o700, "root"), "/boot/grub/grub.cfg": (0o600, "root"),
}


def file_permission_scan(roots: list[str] | None = None, timeout: int = 120) -> dict:
    roots = roots or ["/"]
    findings, suid, world_writable = [], [], []
    # SUID/SGID
    rc, out, _ = run(["find", *roots, "-xdev", "-type", "f", "-perm", "/6000", "-printf", "%p\t%m\t%u\t%g\n"], timeout=timeout)
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 4:
            name = os.path.basename(parts[0])
            item = {"path": parts[0], "mode": parts[1], "owner": parts[2], "group": parts[3], "known": name in KNOWN_SUID}
            suid.append(item)
            if not item["known"]:
                findings.append({"level": "medium", "msg": "非常见 SUID/SGID 文件，请确认来源", "path": parts[0]})
    # 全局可写文件（排除 /proc /sys /tmp 等）
    rc, out, _ = run(["find", *roots, "-xdev", "-type", "f", "-perm", "-0002", "-not", "-path", "/proc/*",
                      "-not", "-path", "/sys/*", "-not", "-path", "/tmp/*", "-not", "-path", "/var/tmp/*",
                      "-not", "-path", "/dev/*", "-printf", "%p\t%m\t%u\n"], timeout=timeout)
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            world_writable.append({"path": parts[0], "mode": parts[1], "owner": parts[2]})
    if world_writable:
        findings.append({"level": "medium", "msg": f"存在 {len(world_writable)} 个全局可写文件", "path": "(见 world_writable)"})
    # 全局可写且无 sticky 的目录
    rc, out, _ = run(["find", *roots, "-xdev", "-type", "d", "-perm", "-0002", "-not", "-perm", "-1000",
                      "-not", "-path", "/proc/*", "-printf", "%p\n"], timeout=timeout)
    for d in out.splitlines():
        findings.append({"level": "medium", "msg": "全局可写目录缺少 sticky 位", "path": d})
    # 敏感文件
    for path, (want, owner) in SENSITIVE.items():
        try:
            st = os.stat(path)
        except OSError:
            continue
        mode = stat.S_IMODE(st.st_mode)
        from ..utils import uid_to_name
        own = uid_to_name(st.st_uid)
        if mode & ~want:
            findings.append({"level": "high", "msg": f"权限过宽 {oct(mode)}，建议 {oct(want)}", "path": path})
        if own != owner:
            findings.append({"level": "high", "msg": f"属主为 {own}，应为 {owner}", "path": path})
    # 用户 .ssh
    from ..utils import home_dirs
    for user, home in home_dirs():
        sshd = os.path.join(home, ".ssh")
        if os.path.isdir(sshd):
            m = stat.S_IMODE(os.stat(sshd).st_mode)
            if m & 0o077:
                findings.append({"level": "medium", "msg": f"{user} 的 .ssh 目录权限 {oct(m)}，应为 0700", "path": sshd})
            for fn in ("authorized_keys", "id_rsa", "id_ed25519", "id_ecdsa"):
                fp = os.path.join(sshd, fn)
                if os.path.isfile(fp):
                    m = stat.S_IMODE(os.stat(fp).st_mode)
                    if m & 0o077:
                        findings.append({"level": "high" if fn.startswith("id_") else "medium",
                                         "msg": f"{fp} 权限 {oct(m)}，应为 0600", "path": fp})
    return {"findings": findings, "suid_sgid": suid, "world_writable": world_writable[:500],
            "note": "" if is_root() else "非 root 运行，部分目录无法扫描"}


# ---------------------------------------------------------------- 汇总
def summary() -> dict:
    users = list_users()
    groups = groups_view()
    return {
        "total_users": len(users),
        "login_users": [u["user"] for u in users if u["can_login"]],
        "admins": [u["user"] for u in users if u["is_admin"]],
        "root_equivalent": [u["user"] for u in users if u["max_level"] in ("root", "root-equiv") and u["user"] != "root"],
        "privileged_groups": {g["group"]: [m["user"] for m in g["members"]] for g in groups
                              if g["level"] in ("root", "root-equiv", "high") and g["members"]},
        "risks": risk_checks(),
        "sudo_findings": sudo_audit()["findings"],
        "ssh_key_total": ssh_keys()["total"],
    }
