"""命令行入口：singularity <模块> <子命令> [参数]，加 --json 输出原始 JSON。"""
from __future__ import annotations

import argparse
import json
import re
import sys

from . import __version__
from .collectors import users, network, processes, environments, logs

LEVEL_COLOR = {"critical": "\033[1;91m", "high": "\033[91m", "error": "\033[91m", "medium": "\033[93m",
               "warning": "\033[93m", "low": "\033[96m", "info": "\033[90m", "debug": "\033[90m"}
RESET = "\033[0m"
USE_COLOR = sys.stdout.isatty()


def c(level: str, text: str) -> str:
    return f"{LEVEL_COLOR.get(level, '')}{text}{RESET}" if USE_COLOR and level in LEVEL_COLOR else text


def table(rows: list[dict], cols: list[str] | None = None, max_width: int = 60) -> None:
    if not rows:
        print("  (空)")
        return
    cols = cols or list(rows[0].keys())
    data = [[_cell(r.get(k), max_width) for k in cols] for r in rows]
    widths = [max(len(str(k)), *(len(d[i]) for d in data)) for i, k in enumerate(cols)]
    print("  " + "  ".join(str(k).ljust(widths[i]) for i, k in enumerate(cols)))
    print("  " + "  ".join("-" * w for w in widths))
    for d in data:
        print("  " + "  ".join(v.ljust(widths[i]) for i, v in enumerate(d)))


def _cell(v, max_width):
    if v is None:
        s = "-"
    elif isinstance(v, bool):
        s = "是" if v else "否"
    elif isinstance(v, (list, tuple)):
        s = ",".join(map(str, v))
    elif isinstance(v, dict):
        s = json.dumps(v, ensure_ascii=False)
    else:
        s = str(v)
    s = s.replace("\n", " ")
    return s if len(s) <= max_width else s[:max_width - 1] + "…"


def findings(items: list[dict], key="msg") -> None:
    if not items:
        print("  " + c("info", "无"))
    for f in items:
        lvl = f.get("level", "info")
        extra = " ".join(f"{k}={v}" for k, v in f.items() if k not in ("level", key, "rule"))
        print(f"  [{c(lvl, lvl.upper().ljust(8))}] {f.get(key)}  {extra}")


def section(title: str) -> None:
    print(f"\n== {title} ==")


DIM = "\033[90m"
BOLD = "\033[1m"


def dim(s: str) -> str:
    return f"{DIM}{s}{RESET}" if USE_COLOR and s else s


def bold(s: str) -> str:
    return f"{BOLD}{s}{RESET}" if USE_COLOR else s


def render_tree(node: dict, prefix: str = "", last: bool = True, root: bool = True, out: list | None = None) -> list[str]:
    """把 {label, note, children} 嵌套结构渲染成 ├── / └── 树。"""
    out = [] if out is None else out
    label = node.get("label", "")
    note = node.get("note") or ""
    line = (bold(label) if root else label) + (f"  {dim(note)}" if note else "")
    out.append(line if root else f"{prefix}{'└── ' if last else '├── '}{line}")
    children = node.get("children") or []
    child_prefix = "" if root else prefix + ("    " if last else "│   ")
    for i, ch in enumerate(children):
        render_tree(ch, child_prefix, i == len(children) - 1, False, out)
    return out


def print_tree(node: dict) -> None:
    print("\n".join(render_tree(node)))


PRIV_COLOR = {"root": "critical", "root-equiv": "high", "high": "high", "medium": "medium",
              "device": "low", "service": "info", "normal": "info", "unknown": "info"}


def priv_tag(level: str) -> str:
    return c(PRIV_COLOR.get(level, "info"), f"[{users.PRIV_LABEL.get(level, level)}]")


def emit(args, data, printer=None):
    if args.json or printer is None:
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
    else:
        printer(data)
    failed = isinstance(data, dict) and (data.get("ok") is False or bool(data.get("error")) or
                                       bool(data.get("audit_error")) or data.get("install_ok") is False)
    if failed and not args.json:
        print(c("error", data.get("audit_error") or data.get("error") or data.get("output") or "操作失败"), file=sys.stderr)
    return 1 if failed else 0


# ---------------------------------------------------------------- 各模块打印
def p_users(d):
    """用户 → 组 → 权限 的树。"""
    pw = {"set": "已设密码", "empty": c("critical", "空密码!"), "locked": "已锁定", "unknown": dim("密码未知(需root)")}
    for u in d:
        flags = [pw.get(u["password"], u["password"])]
        if not u["can_login"]:
            flags.append(dim("不可登录"))
        if u["is_system"]:
            flags.append(dim("系统账号"))
        if u["password_expired"]:
            flags.append(c("medium", "密码过期"))
        head = f"{u['user']}  uid={u['uid']}  {priv_tag(u['max_level'])}"
        grp_children = []
        for g in u["groups"]:
            lvl, desc = users._group_privilege(g, u["gid"] if g == u["primary_group"] else None)
            tag = "(主组)" if g == u["primary_group"] else ""
            show_desc = desc if (lvl != "normal" or g in users.GROUP_PRIVILEGES) and g != u["user"] else ""
            grp_children.append({"label": f"{g} {tag}".strip(), "note": (priv_tag(lvl) + " " + show_desc) if show_desc else ""})
        children = [
            {"label": f"shell {u['shell']}  home {u['home']}" + ("" if u["home_exists"] else c("medium", "  (家目录不存在)")),
             "note": "  ".join(flags)},
            {"label": f"组 ({len(u['groups'])})", "children": grp_children},
        ]
        if u["sudo_rules"]:
            children.append({"label": f"sudo 规则 ({len(u['sudo_rules'])})", "children": [
                {"label": r["raw"], "note": f"来自 {r['via']}" if r["via"] != "user" else f"{r['file']}:{r['line']}"} for r in u["sudo_rules"]]})
        privs = [p for p in u["privileges"] if p["level"] != "normal"]
        if privs:
            children.append({"label": "有效权限", "children": [
                {"label": f"{priv_tag(p['level'])} {p['desc']}", "note": p["source"]} for p in privs]})
        else:
            children.append({"label": dim("有效权限: 仅普通用户")})
        print_tree({"label": head, "children": children})
        print()
    n_root = sum(1 for u in d if u["max_level"] in ("root", "root-equiv"))
    print(dim(f"共 {len(d)} 个账号，{n_root} 个具 root 或等同 root 权限；加 --all 查看系统账号，用 `users groups` 按组查看。"))


def p_groups(d):
    """组 → 成员 的树，带权限说明。"""
    for g in d:
        if g["is_private"]:
            continue
        head = f"{g['group']}  gid={g['gid']}  {priv_tag(g['level'])}"
        members = [{"label": m["user"], "note": "主组" if m["primary"] else ""} for m in g["members"]] or [{"label": dim("(无成员)")}]
        children = [{"label": g["description"] or dim("无特殊权限")}]
        if g["sudo_rules"]:
            children.append({"label": "sudoers", "children": [{"label": r} for r in g["sudo_rules"]]})
        children.append({"label": f"成员 ({g['member_count']})", "children": members})
        print_tree({"label": head, "children": children})
        print()
    private = sum(1 for g in d if g["is_private"])
    print(dim(f"共 {len(d)} 个组（已隐藏 {private} 个与用户同名的私有组）；--all 显示无成员的组。"))


def p_sudo(d):
    section("sudo 规则")
    table(d["rules"], ["file", "who", "runas", "nopasswd", "commands"])
    section("管理组成员")
    for g, m in d["admin_groups"].items():
        print(f"  {g}: {', '.join(m) or '-'}")
    section("发现")
    findings(d["findings"])
    if d["note"]:
        print("  " + d["note"])


def p_sshkeys(d):
    table(d["keys"], ["user", "type", "fingerprint", "comment", "weak", "shared_with", "file_mode"])
    if d["duplicates"]:
        section("多个账号共用同一公钥")
        for fp, us in d["duplicates"].items():
            print(f"  {fp}: {us}")


def p_logins(d):
    section("当前在线")
    table(d["online"])
    section("最近登录")
    table(d["recent_logins"][:20])
    section(f"SSH 失败来源 TOP ({d['window_hours']}h)")
    table([{"ip": ip, "count": n} for ip, n in d["ssh_failed_by_ip"]])
    section("告警")
    findings(d["alerts"])


def p_risks(d):
    findings(d)


def p_perms(d):
    section("发现")
    findings(d["findings"])
    section(f"SUID/SGID ({len(d['suid_sgid'])})")
    table([s for s in d["suid_sgid"] if not s["known"]] or [{"info": "全部为常见系统文件"}])


def p_ports(d):
    table(d, ["proto", "local_ip", "port", "exposure", "service", "pid", "process", "user", "risk"])


def p_conns(d):
    print(f"  总连接: {d['total']}  状态: {d['by_state']}")
    section("远端 IP TOP")
    table([{"ip": a, "count": b} for a, b in d["top_remote_ips"]])
    section("本地端口 TOP")
    table([{"port": a, "count": b} for a, b in d["top_local_ports"]])
    findings(d["alerts"])


def p_fw(d):
    print(f"  生效: {d['active'] or '无'}   {d['note']}")
    for k, v in d["backends"].items():
        state = "unknown" if v["active"] is None else ("active" if v["active"] else "inactive")
        section(f"{k} ({state})")
        print("\n".join("  " + l for l in v["rules"].splitlines()[:60]))


def p_watch(d):
    if d["first_run"]:
        print("  首次运行，已建立基线。" if d["baseline_saved"] else "  首次运行，未保存基线。")
    print(f"  基线时间: {d['baseline_time']}  当前监听: {d['current_count']}")
    findings(d["alerts"])


def p_bw(d):
    table(d["interfaces"], ["iface", "rx_human", "tx_human", "rx_total", "tx_total"])
    if d["per_process"]:
        section("按进程")
        table(d["per_process"])
    elif d["note"]:
        print("  " + d["note"])


def p_procs(d):
    print(f"  负载: {' '.join(d['load'])}  CPU数: {d['cpus']}  进程: {d['total']}  僵尸: {len(d['zombies'])}")
    table(d["processes"], ["pid", "user", "cpu", "mem", "rss_human", "state", "name", "cmdline"])


def p_services(d):
    table(d, ["unit", "active", "sub", "enabled", "description"])


def p_cron(d):
    section("cron")
    table(d["cron"], ["user", "schedule", "description", "command", "source"])
    section("systemd timers")
    table(d["timers"])
    section("周期目录")
    for k, v in d["periodic"].items():
        print(f"  {k}: {', '.join(v)}")
    if d["note"]:
        print("  " + d["note"])


def p_startup(d):
    section("systemd enabled")
    print("  " + "\n  ".join(d["systemd_enabled"]))
    if d["sysv"]:
        section("SysV")
        print("  " + ", ".join(d["sysv"]))
    if d["rc_local"].strip():
        section("rc.local")
        print(d["rc_local"])
    if d["profile_scripts"]:
        section("用户 profile 可疑内容")
        findings([{"level": "medium", "msg": f"{x['user']} {x['file']}: {x['suspicious']}"} for x in d["profile_scripts"]])


def p_python(d):
    section("系统解释器")
    table(d["system"])
    section("venv")
    table(d["venvs"], ["path", "python", "packages", "size", "owner"])
    if d["conda"]:
        section("conda")
        table(d["conda"], ["path", "python", "packages", "size"])
    if d["pyenv"]:
        section("pyenv")
        table(d["pyenv"], ["path", "python", "owner"])
    print("  工具: " + ", ".join(k for k, v in d["tools"].items() if v))


def p_node(d):
    section("系统")
    table([{"tool": k, **v} for k, v in d["system"].items()])
    if d["versions"]:
        section("nvm/fnm 版本")
        table(d["versions"])
    section("全局包")
    table(d["global_packages"])


def p_other(d):
    table([{"runtime": k, **v} for k, v in d["runtimes"].items()])
    for m, items in d["managers"].items():
        section(m)
        table(items)


def p_packages(d):
    print(f"  包管理器: {d['manager']}  已装: {d['installed_count']}  可更新: {d['upgradable_count']}  "
          f"安全更新: {d['security_count']}  需重启: {d['reboot_required']}")
    section("可更新")
    table(d["upgradable"][:50], ["name", "current", "new", "repo", "security"])


def p_docker(d):
    if not d["available"]:
        print("  " + d["note"])
        return
    print(f"  版本 {d['version']}  运行中 {d['running']}/{len(d['containers'])}  镜像 {len(d['images'])}  悬空 {d['dangling_images']}")
    section("容器")
    table(d["containers"], ["Names", "Image", "State", "Status", "cpu", "mem", "Ports"])
    section("磁盘")
    table(d["disk"])
    findings(d["warnings"])


def p_scan(d):
    section("清单")
    table(d["manifests"])
    section(f"漏洞 ({d['vulnerable_count']} 个受影响包)")
    table(d["vulnerabilities"], ["package", "version", "id", "summary", "manifest"])
    if d["error"]:
        print("  " + c("error", d["error"]))


def p_loglist(d):
    print(f"  总大小 {d['total_human']}  文件数 {d['count']}  分区使用 {d['disk_used_pct']}%  剩余 {d['disk_free']}  journal {d['journal_size']}")
    section("最大文件")
    table(d["largest"], ["path", "size_human", "mtime", "rotated"])
    findings(d["alerts"])


def p_loglines(d):
    if d.get("error"):
        print("  " + c("error", d["error"]))
        return
    for r in d["lines"]:
        print(c(r["level"], r["line"]))
    if "level_counts" in d:
        print(f"\n  扫描 {d['scanned']} 行, 匹配 {d['matched']}  级别统计 {d['level_counts']}")


def p_rotate(d):
    print(f"  配置 {len(d['configs'])} 个, 规则块 {d['blocks']}, 上次执行 {d['last_run']}, 触发: {d['timer']}")
    section("问题")
    findings(d["issues"])


def p_anom(d):
    print(f"  窗口 {d['window_hours']}h  来源 {d['sources']}")
    for g in d["groups"]:
        print(f"\n  [{c(g['level'], g['level'].upper())}] {g['description']} ×{g['count']}  单元: {g['units']}")
        for s in g["samples"]:
            print("     " + s)
    if d["failed_units"]:
        section("失败单元")
        print("  " + ", ".join(d["failed_units"]))
    if d["frequent_restarts"]:
        section("频繁重启")
        table(d["frequent_restarts"])


def p_summary(d):
    print(json.dumps(d, ensure_ascii=False, indent=2, default=str))


def p_env_tree(d):
    print_tree(d)
    print()
    print(dim("加 --packages N 在每个 venv/conda 下列出前 N 个包；--size 统计环境体积；`env python` / `env node` 看表格明细。"))


# ---------------------------------------------------------------- 参数解析
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="singularity", description="Linux 服务器管理工具",
                                 epilog="示例: singularity users | singularity env python | singularity --json net ports")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="module")

    u = sub.add_parser("users", help="账号与权限（默认: 用户→组→权限 树）").add_subparsers(dest="cmd")
    ul = u.add_parser("list", help="用户 → 组 → 权限 树状视图")
    ul.add_argument("--all", action="store_true", help="包含系统账号")
    ug = u.add_parser("groups", help="组 → 成员 树状视图，附带该组授予的权限")
    ug.add_argument("--all", action="store_true", help="包含无成员的组")
    u.add_parser("sudo")
    u.add_parser("ssh-keys")
    u.add_parser("logins").add_argument("--hours", type=int, default=24)
    u.add_parser("risks")
    u.add_parser("perms").add_argument("--root", nargs="*", default=None)
    u.add_parser("summary")

    n = sub.add_parser("net", help="网络与端口（默认概览）").add_subparsers(dest="cmd")
    n.add_parser("ports")
    n.add_parser("conns")
    n.add_parser("firewall")
    fr = n.add_parser("fw-rule", help="防火墙放行/拒绝/删除")
    fr.add_argument("action", choices=["allow", "deny", "delete"])
    fr.add_argument("port", type=int)
    fr.add_argument("--proto", default="tcp")
    fr.add_argument("--source")
    n.add_parser("watch", help="与上次快照对比监听端口变化").add_argument("--no-update", action="store_true")
    n.add_parser("bandwidth").add_argument("--interval", type=float, default=1.0)
    n.add_parser("ifaces")
    n.add_parser("summary")

    p = sub.add_parser("proc", help="进程与服务（默认概览）").add_subparsers(dest="cmd")
    pl = p.add_parser("list")
    pl.add_argument("--sort", default="cpu", choices=["cpu", "mem", "rss", "pid", "time"])
    pl.add_argument("--limit", type=int, default=30)
    pl.add_argument("--user")
    pl.add_argument("--search")
    pk = p.add_parser("kill")
    pk.add_argument("pid", type=int)
    pk.add_argument("--signal", default="TERM")
    p.add_parser("tree").add_argument("--root", type=int, default=1)
    ps = p.add_parser("services")
    ps.add_argument("--failed", action="store_true")
    ps.add_argument("--grep")
    sv = p.add_parser("service", help="服务操作: status/start/stop/restart/enable/disable/logs")
    sv.add_argument("action", choices=["status", "start", "stop", "restart", "reload", "enable", "disable", "logs"])
    sv.add_argument("name")
    sv.add_argument("-n", type=int, default=100)
    p.add_parser("cron")
    p.add_parser("cron-history").add_argument("-n", type=int, default=100)
    p.add_parser("startup")
    p.add_parser("summary")

    e = sub.add_parser("env", help="软件与环境（默认: 开发环境树）").add_subparsers(dest="cmd")
    et = e.add_parser("tree", help="开发环境树：语言 → 版本/管理器 → 虚拟环境")
    et.add_argument("--packages", type=int, default=0, metavar="N", help="每个 venv/conda 下列出前 N 个包（会调用 pip，较慢）")
    et.add_argument("--size", action="store_true", help="统计每个环境的磁盘体积（较慢）")
    e.add_parser("python").add_argument("--root", nargs="*")
    e.add_parser("packages-of", help="列出 venv 内的包").add_argument("path")
    e.add_parser("outdated", help="venv 内过期的包").add_argument("path")
    vc = e.add_parser("venv-create")
    vc.add_argument("path")
    vc.add_argument("--python", default="python3")
    vc.add_argument("--install", nargs="*")
    e.add_parser("venv-delete").add_argument("path")
    e.add_parser("export").add_argument("path")
    cl = e.add_parser("clone")
    cl.add_argument("src")
    cl.add_argument("dst")
    e.add_parser("node")
    e.add_parser("other")
    e.add_parser("packages").add_argument("--no-upgradable", action="store_true")
    e.add_parser("pkg-search").add_argument("name")
    pu = e.add_parser("pkg-upgrade")
    pu.add_argument("names", nargs="*")
    pu.add_argument("--security", action="store_true")
    e.add_parser("docker")
    da = e.add_parser("docker-action")
    da.add_argument("target", choices=["container", "image", "volume"])
    da.add_argument("action")
    da.add_argument("name")
    e.add_parser("docker-prune").add_argument("--volumes", action="store_true")
    sc = e.add_parser("scan", help="依赖漏洞扫描 (OSV)")
    sc.add_argument("paths", nargs="*")
    sc.add_argument("--offline", action="store_true")
    e.add_parser("summary")

    l = sub.add_parser("log", help="日志（默认概览）").add_subparsers(dest="cmd")
    l.add_parser("list").add_argument("--top", type=int, default=20)
    rd = l.add_parser("read")
    rd.add_argument("path")
    rd.add_argument("-n", type=int, default=100)
    rd.add_argument("--grep")
    rd.add_argument("--level", choices=logs.LEVEL_ORDER)
    rd.add_argument("-C", type=int, default=0, help="上下文行数")
    l.add_parser("search").add_argument("pattern")
    jn = l.add_parser("journal")
    jn.add_argument("-u", "--unit")
    jn.add_argument("--since", default="1 hour ago")
    jn.add_argument("-p", "--priority")
    jn.add_argument("-n", type=int, default=100)
    jn.add_argument("--grep")
    jn.add_argument("-k", action="store_true")
    l.add_parser("rotate")
    l.add_parser("anomalies").add_argument("--hours", type=int, default=24)
    l.add_parser("summary")

    sub.add_parser("overview", help="全部模块概览")
    return ap


DEFAULT_CMD = {"users": "list", "env": "tree"}


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.module is None:
        parser.print_help()
        return 0
    m = args.module
    cmd = getattr(args, "cmd", None) or DEFAULT_CMD.get(m, "summary")
    # 默认子命令没有经过其子解析器，补上它的默认参数
    for k, v in {"list": {"all": False}, "tree": {"packages": 0, "size": False}}.get(cmd, {}).items():
        if not hasattr(args, k):
            setattr(args, k, v)
    try:
        if m == "overview":
            from .overview import collect
            data = collect()
            status = emit(args, data, p_summary)
            return 1 if any(value.get("error") for value in data.values()) else status
        if m == "users":
            return {
                "list": lambda: emit(args, users.list_users(include_system=args.all), p_users),
                "groups": lambda: emit(args, users.groups_view(include_empty=args.all), p_groups),
                "sudo": lambda: emit(args, users.sudo_audit(), p_sudo),
                "ssh-keys": lambda: emit(args, users.ssh_keys(), p_sshkeys),
                "logins": lambda: emit(args, users.login_audit(args.hours), p_logins),
                "risks": lambda: emit(args, users.risk_checks(), p_risks),
                "perms": lambda: emit(args, users.file_permission_scan(args.root), p_perms),
                "summary": lambda: emit(args, users.summary(), p_summary),
            }[cmd]()
        if m == "net":
            return {
                "ports": lambda: emit(args, network.listening_ports(), p_ports),
                "conns": lambda: emit(args, network.connections(), p_conns),
                "firewall": lambda: emit(args, network.firewall_status(), p_fw),
                "fw-rule": lambda: emit(args, network.firewall_rule(args.action, args.port, args.proto, args.source)),
                "watch": lambda: emit(args, network.port_watch(update=not args.no_update), p_watch),
                "bandwidth": lambda: emit(args, network.bandwidth(args.interval), p_bw),
                "ifaces": lambda: emit(args, network.interfaces(), table),
                "summary": lambda: emit(args, network.summary(), p_summary),
            }[cmd]()
        if m == "proc":
            def svc():
                if args.action == "status":
                    return emit(args, processes.service_detail(args.name), lambda d: print(d.get("status_text") or d))
                if args.action == "logs":
                    return emit(args, processes.service_logs(args.name, args.n), lambda d: print("\n".join(d)))
                return emit(args, processes.service_action(args.name, args.action))
            return {
                "list": lambda: emit(args, processes.list_processes(args.sort, args.limit, user=args.user, search=args.search), p_procs),
                "kill": lambda: emit(args, processes.kill_process(args.pid, args.signal)),
                "tree": lambda: emit(args, processes.process_tree(args.root)),
                "services": lambda: emit(args, processes.services(args.failed, args.grep), p_services),
                "service": svc,
                "cron": lambda: emit(args, processes.cron_jobs(), p_cron),
                "cron-history": lambda: emit(args, processes.cron_history(args.n), lambda d: print("\n".join(d))),
                "startup": lambda: emit(args, processes.startup_items(), p_startup),
                "summary": lambda: emit(args, processes.summary(), p_summary),
            }[cmd]()
        if m == "env":
            return {
                "tree": lambda: emit(args, environments.dev_tree(include_size=args.size, with_packages=args.packages), p_env_tree),
                "python": lambda: emit(args, environments.python_envs(args.root), p_python),
                "packages-of": lambda: emit(args, environments.env_packages(args.path), table),
                "outdated": lambda: emit(args, environments.env_outdated(args.path), table),
                "venv-create": lambda: emit(args, environments.create_venv(args.path, args.python, args.install)),
                "venv-delete": lambda: emit(args, environments.delete_venv(args.path)),
                "export": lambda: emit(args, environments.export_env(args.path), lambda d: print(d["requirements"] or d["error"])),
                "clone": lambda: emit(args, environments.clone_env(args.src, args.dst)),
                "node": lambda: emit(args, environments.node_envs(), p_node),
                "other": lambda: emit(args, environments.other_languages(), p_other),
                "packages": lambda: emit(args, environments.packages(not args.no_upgradable), p_packages),
                "pkg-search": lambda: emit(args, environments.package_search(args.name), table),
                "pkg-upgrade": lambda: emit(args, environments.package_upgrade(args.names or None, args.security)),
                "docker": lambda: emit(args, environments.docker_info(), p_docker),
                "docker-action": lambda: emit(args, environments.docker_action(args.target, args.action, args.name)),
                "docker-prune": lambda: emit(args, environments.docker_prune(args.volumes)),
                "scan": lambda: emit(args, environments.dependency_scan(args.paths or None, online=not args.offline), p_scan),
                "summary": lambda: emit(args, environments.summary(), p_summary),
            }[cmd]()
        if m == "log":
            return {
                "list": lambda: emit(args, logs.list_logs(top=args.top), p_loglist),
                "read": lambda: emit(args, logs.read_log(args.path, args.n, args.grep, args.level, context=args.C), p_loglines),
                "search": lambda: emit(args, logs.search_logs(args.pattern), lambda d: table(d["hits"])),
                "journal": lambda: emit(args, logs.journal(args.unit, args.since, args.priority, args.n, args.grep, args.k), p_loglines),
                "rotate": lambda: emit(args, logs.logrotate_check(), p_rotate),
                "anomalies": lambda: emit(args, logs.anomalies(args.hours), p_anom),
                "summary": lambda: emit(args, logs.summary(), p_summary),
            }[cmd]()
    except KeyboardInterrupt:
        return 130
    except PermissionError as e:
        return emit(args, {"ok": False, "error": f"权限不足: {e}（部分功能需要 root）"})
    except (ValueError, OSError, re.error) as e:
        return emit(args, {"ok": False, "error": str(e)})


if __name__ == "__main__":
    sys.exit(main())
