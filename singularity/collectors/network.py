"""模块2：网络与端口 —— 监听端口与进程关联、防火墙、连接状态、端口变化告警、带宽监控。"""
from __future__ import annotations

import collections
import glob
import ipaddress
import json
import math
import os
import re
import socket
import struct
import tempfile
import time

from ..utils import run, which, read_lines, read_text, data_dir, pid_user, pid_cmdline, pid_name, now_iso, audit_result

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
    "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}
WELL_KNOWN = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
    143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "submission", 631: "cups", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker(!)", 2376: "docker-tls",
    3000: "dev-web", 3306: "mysql", 3389: "rdp", 5000: "dev-web", 5432: "postgres", 5672: "amqp",
    5900: "vnc", 6379: "redis", 6443: "k8s-api", 8000: "dev-web", 8080: "http-alt", 8443: "https-alt",
    9000: "php-fpm", 9090: "prometheus", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}
RISKY_PUBLIC = {23, 111, 445, 2375, 3306, 5432, 6379, 9200, 11211, 27017, 5900, 2049}


# ---------------------------------------------------------------- 监听端口
def _hex_addr(hexaddr: str, v6: bool) -> tuple[str, int]:
    ip_hex, port_hex = hexaddr.split(":")
    port = int(port_hex, 16)
    if v6:
        raw = bytes.fromhex(ip_hex)
        # /proc 中 IPv6 以 4 个小端 32bit 字存储
        words = [struct.pack("<I", struct.unpack(">I", raw[i:i + 4])[0]) for i in range(0, 16, 4)]
        ip = socket.inet_ntop(socket.AF_INET6, b"".join(words))
        if ip.startswith("::ffff:"):
            ip = ip[7:]
    else:
        ip = socket.inet_ntoa(struct.pack("<I", int(ip_hex, 16)))
    return ip, port


def _inode_pid_map() -> dict[str, int]:
    """socket inode -> pid（只能看到自己有权限的进程，root 可看全部）。"""
    m = {}
    for fd in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            link = os.readlink(fd)
        except OSError:
            continue
        if link.startswith("socket:["):
            m[link[8:-1]] = int(fd.split("/")[2])
    return m


def _proc_sockets(listen_only: bool) -> list[dict]:
    """直接解析 /proc/net/{tcp,tcp6,udp,udp6}。"""
    inode_pid = _inode_pid_map()
    rows = []
    for proto, path, v6 in (("tcp", "/proc/net/tcp", False), ("tcp", "/proc/net/tcp6", True),
                            ("udp", "/proc/net/udp", False), ("udp", "/proc/net/udp6", True)):
        for line in read_lines(path)[1:]:
            p = line.split()
            if len(p) < 10:
                continue
            state = TCP_STATES.get(p[3], p[3]) if proto == "tcp" else ("UNCONN" if p[3] == "07" else "ESTAB")
            if listen_only and not (state == "LISTEN" or (proto == "udp" and p[3] == "07")):
                continue
            lip, lport = _hex_addr(p[1], v6)
            rip, rport = _hex_addr(p[2], v6)
            pid = inode_pid.get(p[9])
            rows.append({"proto": proto + ("6" if v6 else ""), "state": state, "local_ip": lip, "local_port": lport,
                         "remote_ip": rip, "remote_port": rport, "pid": pid, "uid": int(p[7])})
    return rows


def _parse_ss_process(s: str) -> list[tuple[str, int]]:
    return [(m.group(1), int(m.group(2))) for m in re.finditer(r'\("([^"]+)",pid=(\d+)', s)]


def _split_addr(addr: str) -> tuple[str, int | str]:
    """'0.0.0.0:22' / '[::]:22' / '*:22' / '127.0.0.1%lo:53' -> (ip, port)"""
    host, _, port = addr.rpartition(":")
    host = host.strip("[]").split("%")[0]
    return host, (int(port) if port.isdigit() else port)


def listening_ports() -> list[dict]:
    rows = []
    rc, out, _ = run(["ss", "-tulpnH"])
    if rc == 0 and out.strip():
        for line in out.splitlines():
            p = line.split()
            if len(p) < 5:
                continue
            proto, state, local = p[0], p[1], p[4]
            ip, port = _split_addr(local)
            procs = _parse_ss_process(line)
            pid = procs[0][1] if procs else None
            rows.append({"proto": proto, "local_ip": ip, "port": port, "pid": pid,
                         "process": procs[0][0] if procs else None, "all_pids": [x[1] for x in procs]})
    else:
        for s in _proc_sockets(listen_only=True):
            rows.append({"proto": s["proto"].removesuffix("6"), "local_ip": s["local_ip"], "port": s["local_port"], "pid": s["pid"],
                         "process": pid_name(s["pid"]) if s["pid"] else None, "all_pids": [s["pid"]] if s["pid"] else []})
    for r in rows:
        ip = r["local_ip"]
        r["exposure"] = "public" if ip in ("0.0.0.0", "::", "*", "") else ("local" if ip.startswith(("127.", "::1")) else "interface")
        r["user"] = pid_user(r["pid"]) if r["pid"] else "?"
        r["cmdline"] = pid_cmdline(r["pid"])[:120] if r["pid"] else ""
        r["service"] = WELL_KNOWN.get(r["port"] if isinstance(r["port"], int) else -1, "")
        r["risk"] = "high" if (r["exposure"] == "public" and r["port"] in RISKY_PUBLIC) else ""
    rows.sort(key=lambda x: (x["proto"], x["port"] if isinstance(x["port"], int) else 0))
    # 去重（同一端口 v4/v6 两条合并显示）
    return rows


# ---------------------------------------------------------------- 连接状态
def connections(top: int = 20) -> dict:
    conns = []
    rc, out, _ = run(["ss", "-tanH"])
    if rc == 0:
        for line in out.splitlines():
            p = line.split()
            if len(p) >= 5:
                lip, lport = _split_addr(p[3])
                rip, rport = _split_addr(p[4])
                conns.append({"state": p[0], "local_ip": lip, "local_port": lport, "remote_ip": rip, "remote_port": rport})
    else:
        for s in _proc_sockets(listen_only=False):
            if s["proto"].startswith("tcp"):
                conns.append({"state": s["state"], "local_ip": s["local_ip"], "local_port": s["local_port"],
                              "remote_ip": s["remote_ip"], "remote_port": s["remote_port"]})
    by_state = collections.Counter(c["state"] for c in conns)
    by_remote = collections.Counter(c["remote_ip"] for c in conns if c["state"] in ("ESTAB", "ESTABLISHED"))
    by_local_port = collections.Counter(c["local_port"] for c in conns if c["state"] in ("ESTAB", "ESTABLISHED"))
    alerts = []
    for ip, n in by_remote.most_common(5):
        if n >= 100:
            alerts.append({"level": "medium", "msg": f"{ip} 建立了 {n} 个连接"})
    if by_state.get("TIME-WAIT", 0) + by_state.get("TIME_WAIT", 0) > 5000:
        alerts.append({"level": "low", "msg": "TIME_WAIT 数量过多，考虑调整 net.ipv4.tcp_tw_reuse"})
    if by_state.get("SYN-RECV", 0) + by_state.get("SYN_RECV", 0) > 200:
        alerts.append({"level": "high", "msg": "SYN_RECV 过多，可能遭受 SYN flood"})
    return {"total": len(conns), "by_state": dict(by_state), "top_remote_ips": by_remote.most_common(top),
            "top_local_ports": by_local_port.most_common(top), "alerts": alerts}


# ---------------------------------------------------------------- 防火墙
def firewall_status() -> dict:
    backends = {}
    if which("ufw"):
        rc, out, err = run(["ufw", "status", "verbose"])
        backends["ufw"] = {"available": True, "active": "Status: active" in out if rc == 0 else None,
                           "rules": out.strip() or err.strip(), "error": err.strip() if rc else ""}
    if which("firewall-cmd"):
        rc, state, err = run(["firewall-cmd", "--state"])
        active = True if rc == 0 and state.strip() == "running" else (
            False if rc == 252 or state.strip() == "not running" else None)
        info = ""
        if active:
            rc, info, err = run(["firewall-cmd", "--list-all"])
        backends["firewalld"] = {"available": True, "active": active, "rules": (info or state or err).strip(),
                                "error": err.strip() if rc else ""}
    if which("nft"):
        rc, out, err = run(["nft", "list", "ruleset"])
        backends["nftables"] = {"available": True, "active": bool(out.strip()) if rc == 0 else None,
                                "rules": (out or err).strip()[:20000], "error": err.strip() if rc else ""}
    if which("iptables"):
        rc, out, err = run(["iptables", "-S"])
        rules = out.strip()
        non_default = [l for l in rules.splitlines() if not l.startswith("-P")]
        backends["iptables"] = {"available": True, "active": (bool(non_default) or any("DROP" in l for l in rules.splitlines() if l.startswith("-P"))) if rc == 0 else None,
                                "rules": (rules or err.strip())[:20000],
                                "error": err.strip() if rc else "",
                                "nat": run(["iptables", "-t", "nat", "-S"])[1].strip()[:5000]}
    active = [k for k, v in backends.items() if v.get("active")]
    unknown = [k for k, v in backends.items() if v.get("active") is None or v.get("error")]
    note = ""
    if unknown:
        note = f"无法完整读取防火墙状态（{', '.join(unknown)}），请检查权限或服务状态；不能据此判断端口是否可从外部访问"
    elif not active:
        note = "未检测到本机生效的防火墙规则；实际可达性还取决于监听地址、路由及上游防火墙"
    elif len(active) > 1 and "ufw" in active and "iptables" in active:
        note = "ufw 底层使用 iptables，两者显示同一套规则属正常"
    return {"backends": backends, "active": active, "unknown": unknown, "note": note, "manager": _firewall_manager(backends)}


def _firewall_manager(backends: dict) -> str:
    for k in ("ufw", "firewalld", "nftables", "iptables"):
        if backends.get(k, {}).get("active"):
            return k
    return ""


def firewall_rule(action: str, port: int, proto: str = "tcp", source: str | None = None, actor: str = "cli") -> dict:
    """新增/删除放行规则（allow/deny/delete），自动选用 ufw / firewalld / iptables。"""
    if action not in ("allow", "deny", "delete"):
        return {"ok": False, "error": "action must be allow/deny/delete"}
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return {"ok": False, "error": "port must be between 1 and 65535"}
    if proto not in ("tcp", "udp"):
        return {"ok": False, "error": "proto must be tcp/udp"}
    if source:
        try:
            source = str(ipaddress.ip_network(source, strict=False))
        except ValueError:
            return {"ok": False, "error": "source must be an IP address or CIDR network"}
    status = firewall_status()
    mgr = status["manager"]
    if not mgr:
        if status.get("unknown"):
            return {"ok": False, "error": "无法确定防火墙管理器，请先确认权限与服务状态"}
        mgr = next((m for m in ("ufw", "firewalld", "iptables", "nftables") if m in status["backends"]), "")
    if mgr not in ("ufw", "firewalld", "iptables"):
        return {"ok": False, "manager": mgr, "error": "nftables 仅支持查看，请使用原生规则工具" if mgr else "未找到支持的防火墙管理器"}
    if mgr == "ufw":
        cmd = ["ufw", "--force"] + (["delete"] if action == "delete" else []) + ["allow" if action != "deny" else "deny"]
        cmd += ["from", source, "to", "any", "port", str(port), "proto", proto] if source else [f"{port}/{proto}"]
    elif mgr == "firewalld":
        if source or action == "deny":
            family = f' family="ipv{ipaddress.ip_network(source).version}"' if source else ""
            src = f' source address="{source}"' if source else ""
            rule = f'rule{family}{src} port port="{port}" protocol="{proto}" {"drop" if action == "deny" else "accept"}'
            op = "--remove-rich-rule" if action == "delete" else "--add-rich-rule"
            cmd = ["firewall-cmd", "--permanent", f"{op}={rule}"]
        else:
            op = "--remove-port" if action == "delete" else "--add-port"
            cmd = ["firewall-cmd", "--permanent", f"{op}={port}/{proto}"]
    else:
        flag = "-D" if action == "delete" else "-I"
        binary = "ip6tables" if source and ipaddress.ip_network(source).version == 6 else "iptables"
        cmd = [binary, flag, "INPUT", "-p", proto, "--dport", str(port)] + (["-s", source] if source else []) \
            + ["-j", "DROP" if action == "deny" else "ACCEPT"]
    rc, out, err = run(cmd)
    res = {"manager": mgr, "command": " ".join(cmd), "ok": rc == 0, "output": (out + err).strip()}
    if mgr == "firewalld" and rc == 0:
        rc, out, err = run(["firewall-cmd", "--reload"])
        res.update(ok=rc == 0, reload_output=(out + err).strip())
        if rc:
            res["error"] = "永久规则已修改，但 reload 失败；运行时规则未确认生效"
    return audit_result("firewall", res, actor)


# ---------------------------------------------------------------- 端口变化监控
def _snapshot_path():
    return data_dir() / "ports_snapshot.json"


def port_watch(update: bool = True) -> dict:
    """与上次快照对比，返回新增/消失的监听端口。首次运行只建立基线。"""
    current = listening_ports()
    key = lambda r: f"{r['proto']}:{r['local_ip']}:{r['port']}"
    cur_map = {key(r): r for r in current}
    path = _snapshot_path()
    prev = None
    if path.exists():
        try:
            prev = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(prev, dict) or not isinstance(prev.get("ports"), dict) or any(
                    not isinstance(r, dict) or not all(k in r for k in ("proto", "local_ip", "port", "process", "user", "exposure"))
                    for r in prev["ports"].values()):
                raise ValueError("invalid snapshot structure")
        except (OSError, ValueError) as exc:
            return {"ok": False, "error": f"无法读取端口基线，原文件已保留: {exc}", "alerts": [],
                    "added": [], "removed": [], "process_changed": [], "current_count": len(current),
                    "first_run": False, "baseline_time": None, "baseline_saved": False}
    prev_map = prev["ports"] if prev is not None else {}
    added = [cur_map[k] for k in cur_map if k not in prev_map] if prev is not None else []
    removed = [prev_map[k] for k in prev_map if k not in cur_map]
    changed = [{"key": k, "before": prev_map[k].get("process"), "after": cur_map[k].get("process")}
               for k in cur_map if k in prev_map and prev_map[k].get("process") != cur_map[k].get("process")]
    alerts = []
    for r in added:
        lvl = "high" if r["exposure"] == "public" else "medium"
        alerts.append({"level": lvl, "msg": f"新增监听 {r['proto']} {r['local_ip']}:{r['port']} 进程 {r['process']} ({r['user']})"})
    for r in removed:
        alerts.append({"level": "low", "msg": f"监听消失 {r['proto']} {r['local_ip']}:{r['port']} 原进程 {r.get('process')}"})
    for r in changed:
        alerts.append({"level": "medium", "msg": f"监听进程变更 {r['key']}: {r['before']} → {r['after']}"})
    result = {"baseline_time": prev.get("time") if prev is not None else None, "first_run": prev is None,
              "added": added, "removed": removed, "process_changed": changed, "alerts": alerts,
              "current_count": len(current), "baseline_saved": False}
    if update:
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as f:
                tmp_path = f.name
                json.dump({"time": now_iso(), "ports": cur_map}, f, ensure_ascii=False, indent=1)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
            result["baseline_saved"] = True
        except OSError as exc:
            result.update(ok=False, error=f"保存端口基线失败: {exc}")
        finally:
            if tmp_path is not None and os.path.exists(tmp_path):
                os.unlink(tmp_path)
    return result


# ---------------------------------------------------------------- 带宽
def _read_net_dev() -> dict[str, tuple[int, int]]:
    res = {}
    for line in read_lines("/proc/net/dev")[2:]:
        if ":" not in line:
            continue
        name, data = line.split(":", 1)
        f = data.split()
        res[name.strip()] = (int(f[0]), int(f[8]))  # rx_bytes, tx_bytes
    return res


def bandwidth(interval: float = 1.0) -> dict:
    if not math.isfinite(interval) or interval <= 0:
        raise ValueError("interval must be finite and greater than 0")
    a = _read_net_dev()
    started = time.monotonic()
    time.sleep(interval)
    b = _read_net_dev()
    elapsed = max(time.monotonic() - started, 1e-9)
    ifaces = []
    for name in b:
        if name == "lo" or name not in a:
            continue
        rx = max(0, b[name][0] - a[name][0]) / elapsed
        tx = max(0, b[name][1] - a[name][1]) / elapsed
        ifaces.append({"iface": name, "rx_bps": int(rx), "tx_bps": int(tx), "rx_total": b[name][0], "tx_total": b[name][1],
                       "rx_human": f"{rx / 1024:.1f} KB/s", "tx_human": f"{tx / 1024:.1f} KB/s"})
    # 按进程的流量：内核不直接提供，若安装了 nethogs 则调用一次
    per_proc = []
    if which("nethogs"):
        rc, out, _ = run(["nethogs", "-t", "-c", "2", "-d", str(int(max(1, interval)))], timeout=15)
        for line in out.splitlines():
            p = line.rsplit("\t", 2)
            if len(p) == 3 and not line.startswith("Refreshing"):
                try:
                    per_proc.append({"process": p[0], "tx_kbps": float(p[1]), "rx_kbps": float(p[2])})
                except ValueError:
                    pass
    return {"interval": interval, "interfaces": ifaces, "per_process": per_proc[:30],
            "note": "" if per_proc else "按进程流量需要安装 nethogs"}


def interfaces() -> list[dict]:
    rc, out, _ = run(["ip", "-j", "addr"])
    if rc == 0:
        try:
            data = json.loads(out)
            return [{"name": i["ifname"], "state": i.get("operstate"), "mac": i.get("address"),
                     "addrs": [f"{a['local']}/{a['prefixlen']}" for a in i.get("addr_info", [])]} for i in data]
        except (json.JSONDecodeError, KeyError):
            pass
    return [{"name": n} for n in _read_net_dev()]


def summary() -> dict:
    ports = listening_ports()
    fw = firewall_status()
    return {
        "listening": len(ports),
        "public": [f"{p['proto']}/{p['port']} {p['process']}" for p in ports if p["exposure"] == "public"],
        "risky": [p for p in ports if p["risk"]],
        "firewall": fw["active"] or "none",
        "firewall_note": fw["note"],
        "connections": connections(5),
    }
