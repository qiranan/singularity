"""模块5：软件与环境 —— Python/Node/Java/Go/Rust 环境、系统包管理、Docker、依赖漏洞扫描、环境导出克隆。"""
from __future__ import annotations

import glob
import json
import os
import re
import shlex
import shutil
import tempfile
import urllib.request

from ..utils import run, which, read_lines, read_text, home_dirs, audit_result, human_bytes

SCAN_ROOTS = ["/opt", "/srv", "/var/www", "/home", "/root", "/app", "/data", "/workspace"]
SKIP_DIRS = {"node_modules", ".git", "site-packages", "__pycache__", ".cache", "proc", "sys", ".npm", ".cargo", "snap"}
KEEP_HIDDEN = {".venv", ".virtualenvs", ".pyenv", ".conda"}


def _dir_size(path: str, limit_files: int = 200000) -> int:
    total, n = 0, 0
    for root, dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
            n += 1
            if n > limit_files:
                return total
    return total


def _walk_find(filename: str, roots: list[str], max_depth: int = 5) -> list[str]:
    found = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        base_depth = root.rstrip("/").count("/")
        for cur, dirs, files in os.walk(root):
            depth = cur.count("/") - base_depth
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and (not d.startswith(".") or d in KEEP_HIDDEN)]
            if depth >= max_depth:
                dirs[:] = []
            if filename in files:
                found.append(cur)
                if filename == "pyvenv.cfg":
                    dirs[:] = []  # 仅环境边界停止深入，项目清单仍扫描子项目
    return found


def _outer_roots(roots: list[str]) -> list[str]:
    """去掉已被其他根目录包含的路径，避免重复遍历（如 /home 与 /home/alice）。"""
    result = []
    for root in sorted(set(roots)):
        if not any(root.startswith(other.rstrip("/") + "/") for other in result):
            result.append(root)
    return result


# ---------------------------------------------------------------- Python
def _venv_info(path: str, kind: str, include_size: bool = True) -> dict:
    cfg = {}
    for line in read_lines(os.path.join(path, "pyvenv.cfg")):
        if "=" in line:
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip()
    py = os.path.join(path, "bin", "python")
    sp = glob.glob(os.path.join(path, "lib", "python*", "site-packages"))
    pkgs = 0
    if sp:
        pkgs = len([d for d in os.listdir(sp[0]) if d.endswith((".dist-info", ".egg-info"))])
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        mtime = 0
    return {"kind": kind, "path": path, "python": cfg.get("version") or cfg.get("version_info") or _py_version(py),
            "base": cfg.get("home"), "packages": pkgs, "size": human_bytes(_dir_size(path)) if include_size else None, "mtime": mtime,
            "owner": _owner(path), "has_pip": os.path.exists(os.path.join(path, "bin", "pip"))}


def _owner(path):
    from ..utils import uid_to_name
    try:
        return uid_to_name(os.stat(path).st_uid)
    except OSError:
        return "?"


def _py_version(exe: str) -> str:
    rc, out, err = run([exe, "--version"], timeout=5)
    return (out + err).strip().replace("Python ", "") if rc == 0 else ""


def python_envs(extra_roots: list[str] | None = None, include_size: bool = True) -> dict:
    roots = SCAN_ROOTS + [h for _, h in home_dirs()] + (extra_roots or []) + [os.getcwd()]
    roots = _outer_roots([r for r in roots if os.path.isdir(r)])
    venvs = [_venv_info(p, "venv", include_size) for p in sorted(set(_walk_find("pyvenv.cfg", roots)))]
    # conda
    conda_envs = []
    conda = which("conda") or next((p for p in glob.glob("/opt/*conda*/bin/conda") + glob.glob("/home/*/*conda*/bin/conda") + glob.glob("/root/*conda*/bin/conda")), None)
    if conda:
        rc, out, _ = run([conda, "env", "list", "--json"], timeout=30)
        if rc == 0:
            try:
                for p in json.loads(out).get("envs", []):
                    conda_envs.append(_venv_info(p, "conda", include_size) | {"python": _py_version(os.path.join(p, "bin", "python"))})
            except json.JSONDecodeError:
                pass
    # pyenv
    pyenv_versions = []
    for _, home in home_dirs():
        for p in glob.glob(os.path.join(home, ".pyenv", "versions", "*")):
            pyenv_versions.append({"kind": "pyenv", "path": p, "python": os.path.basename(p), "owner": _owner(p)})
    # 系统解释器
    system = []
    seen = set()
    for name in ("python3", "python", "python2", "python3.8", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13"):
        exe = which(name)
        if exe and os.path.realpath(exe) not in seen:
            seen.add(os.path.realpath(exe))
            system.append({"name": name, "path": os.path.realpath(exe), "version": _py_version(exe)})
    tools = {t: bool(which(t)) for t in ("pip", "pip3", "pipx", "poetry", "pdm", "uv", "pyenv", "conda", "virtualenv")}
    return {"venvs": venvs, "conda": conda_envs, "pyenv": pyenv_versions, "system": system, "tools": tools,
            "scanned_roots": roots}


def env_packages(path: str) -> list[dict]:
    """列出某个 venv/conda 环境里安装的包。"""
    py = os.path.join(path, "bin", "python")
    if not os.path.exists(py):
        return []
    rc, out, _ = run([py, "-m", "pip", "list", "--format", "json", "--disable-pip-version-check"], timeout=60)
    try:
        return json.loads(out) if rc == 0 else []
    except json.JSONDecodeError:
        return []


def env_outdated(path: str) -> list[dict]:
    py = os.path.join(path, "bin", "python")
    rc, out, _ = run([py, "-m", "pip", "list", "--outdated", "--format", "json", "--disable-pip-version-check"], timeout=120)
    try:
        return json.loads(out) if rc == 0 else []
    except json.JSONDecodeError:
        return []


def create_venv(path: str, python: str = "python3", packages: list[str] | None = None, actor: str = "cli") -> dict:
    if os.path.exists(path):
        return {"ok": False, "error": "path exists"}
    rc, out, err = run([python, "-m", "venv", path], timeout=120)
    if rc != 0:
        return {"ok": False, "error": err.strip() or out.strip()}
    res = {"ok": True, "path": path}
    if packages:
        rc, out, err = run([os.path.join(path, "bin", "pip"), "install", *packages], timeout=600)
        res["install_ok"] = rc == 0
        res["install_output"] = (out + err)[-2000:]
    return audit_result("venv.create", res, actor, {"path": path, "python": python, **res})


def delete_venv(path: str, actor: str = "cli") -> dict:
    if not os.path.isfile(os.path.join(path, "pyvenv.cfg")):
        return {"ok": False, "error": "不是一个 venv 目录（缺少 pyvenv.cfg），拒绝删除"}
    shutil.rmtree(path)
    return audit_result("venv.delete", {"ok": True, "path": path}, actor)


def export_env(path: str) -> dict:
    """导出 requirements.txt 内容，可用于在另一台机器克隆。"""
    py = os.path.join(path, "bin", "python")
    rc, out, err = run([py, "-m", "pip", "freeze", "--disable-pip-version-check"], timeout=60)
    cfg = {k.strip(): v.strip() for k, v in (l.split("=", 1) for l in read_lines(os.path.join(path, "pyvenv.cfg")) if "=" in l)}
    version = re.match(r"\d+\.\d+", cfg.get("version", ""))
    python = "python" + (version.group() if version else "3")
    target = os.path.basename(os.path.normpath(path))
    return {"ok": rc == 0, "python": cfg.get("version"), "requirements": out, "error": err.strip() if rc else "",
            "clone_script": f"{python} -m venv {shlex.quote(target)} && "
                            f"{shlex.quote(target + '/bin/python')} -m pip install -r requirements.txt"}


def clone_env(src: str, dst: str, actor: str = "cli") -> dict:
    exp = export_env(src)
    if not exp["ok"]:
        return {"ok": False, "error": exp["error"]}
    base_py = os.path.join(src, "bin", "python")
    res = create_venv(dst, base_py, actor=actor)
    if not res["ok"]:
        return res
    with tempfile.TemporaryDirectory(prefix="singularity-clone-") as directory:
        req = os.path.join(directory, "requirements.txt")
        with open(req, "w", encoding="utf-8") as output:
            output.write(exp["requirements"])
        rc, out, err = run([os.path.join(dst, "bin", "pip"), "install", "-r", req], timeout=900)
    result = {"ok": rc == 0, "src": src, "dst": dst, "output": (out + err)[-3000:]}
    if res.get("audit_error"):
        result["audit_error"] = res["audit_error"]
    return audit_result("venv.clone", result, actor)


# ---------------------------------------------------------------- Node / 其它语言
def node_envs() -> dict:
    nvm = []
    for user, home in home_dirs():
        for p in glob.glob(os.path.join(home, ".nvm", "versions", "node", "*")):
            nvm.append({"user": user, "version": os.path.basename(p), "path": p})
        for p in glob.glob(os.path.join(home, ".fnm", "node-versions", "*")) + glob.glob(os.path.join(home, ".local/share/fnm/node-versions/*")):
            nvm.append({"user": user, "version": os.path.basename(p), "path": p, "manager": "fnm"})
    system = {}
    for t in ("node", "npm", "yarn", "pnpm", "bun", "deno"):
        exe = which(t)
        if exe:
            system[t] = {"path": exe, "version": run([exe, "--version"], timeout=10)[1].strip()}
    globals_ = []
    if which("npm"):
        rc, out, _ = run(["npm", "ls", "-g", "--depth=0", "--json"], timeout=30)
        try:
            globals_ = [{"name": k, "version": v.get("version")} for k, v in json.loads(out).get("dependencies", {}).items()]
        except json.JSONDecodeError:
            pass
    projects = [{"path": p, "has_node_modules": os.path.isdir(os.path.join(p, "node_modules"))}
                for p in _walk_find("package.json", [r for r in SCAN_ROOTS if os.path.isdir(r)], max_depth=4)]
    return {"versions": nvm, "system": system, "global_packages": globals_, "projects": projects[:100]}


def other_languages() -> dict:
    res = {}
    checks = {
        "java": (["java", "-version"], r"version \"?([\d._]+)"), "javac": (["javac", "-version"], r"([\d._]+)"),
        "go": (["go", "version"], r"go([\d.]+)"), "rustc": (["rustc", "--version"], r"([\d.]+)"),
        "cargo": (["cargo", "--version"], r"([\d.]+)"), "ruby": (["ruby", "--version"], r"([\d.]+)"),
        "php": (["php", "--version"], r"PHP ([\d.]+)"), "perl": (["perl", "-e", "print $]"], r"([\d.]+)"),
        "gcc": (["gcc", "--version"], r"([\d.]+)"), "dotnet": (["dotnet", "--version"], r"([\d.]+)"),
    }
    for name, (cmd, pat) in checks.items():
        if which(cmd[0]):
            rc, out, err = run(cmd, timeout=10)
            m = re.search(pat, out + err)
            res[name] = {"path": which(cmd[0]), "version": m.group(1) if m else (out + err).strip()[:60]}
    # 版本管理器
    managers = {}
    for user, home in home_dirs():
        for mgr, sub in (("sdkman", ".sdkman/candidates/*/*"), ("gvm", ".gvm/gos/*"), ("rustup", ".rustup/toolchains/*"),
                         ("rbenv", ".rbenv/versions/*"), ("rvm", ".rvm/rubies/*"), ("asdf", ".asdf/installs/*/*")):
            hits = [p for p in glob.glob(os.path.join(home, sub)) if not p.endswith("current")]
            if hits:
                managers.setdefault(mgr, []).extend({"user": user, "path": p} for p in hits)
    return {"runtimes": res, "managers": managers}


# ---------------------------------------------------------------- 系统包
def _pkg_manager() -> str:
    for m in ("apt", "dnf", "yum", "pacman", "apk", "zypper"):
        if which(m):
            return m
    return ""


def packages(upgradable: bool = True) -> dict:
    mgr = _pkg_manager()
    res = {"manager": mgr, "installed_count": 0, "upgradable": [], "security": [], "reboot_required": False}
    if mgr == "apt":
        rc, out, err = run(["dpkg-query", "-W", "-f=${Package}\n"], timeout=60)
        res["installed_count"] = len([l for l in out.splitlines() if l])
        if rc:
            res["error"] = err.strip() or "dpkg-query failed"
        if upgradable:
            rc, out, err = run(["apt", "list", "--upgradable"], timeout=60)
            if rc:
                res["error"] = err.strip() or "apt list failed"
            for line in out.splitlines():
                m = re.match(r"^([^/]+)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]", line)
                if m:
                    item = {"name": m.group(1), "repo": m.group(2), "new": m.group(3), "current": m.group(4),
                            "security": "security" in m.group(2)}
                    res["upgradable"].append(item)
                    if item["security"]:
                        res["security"].append(item)
        res["reboot_required"] = os.path.exists("/var/run/reboot-required")
        res["last_update"] = _mtime("/var/lib/apt/periodic/update-success-stamp") or _mtime("/var/cache/apt/pkgcache.bin")
    elif mgr in ("dnf", "yum"):
        res["installed_count"] = len(run(["rpm", "-qa"], timeout=60)[1].splitlines())
        if upgradable:
            rc, out, _ = run([mgr, "-q", "check-update"], timeout=120)
            for line in out.splitlines():
                p = line.split()
                if len(p) == 3 and "." in p[0]:
                    res["upgradable"].append({"name": p[0], "new": p[1], "repo": p[2], "security": False})
            rc, out, _ = run([mgr, "-q", "updateinfo", "list", "security"], timeout=120)
            sec = set()
            for line in out.splitlines():
                p = line.split()
                if len(p) >= 3:
                    sec.add(p[-1])
                    res["security"].append({"advisory": p[0], "severity": p[1], "package": p[-1]})
            for u in res["upgradable"]:
                u["security"] = any(u["name"].split(".")[0] in s for s in sec)
        if which("needs-restarting"):
            res["reboot_required"] = run(["needs-restarting", "-r"])[0] == 1
    elif mgr == "pacman":
        res["installed_count"] = len(run(["pacman", "-Qq"])[1].splitlines())
        if upgradable:
            for line in run(["pacman", "-Qu"], timeout=60)[1].splitlines():
                p = line.split()
                if len(p) >= 4:
                    res["upgradable"].append({"name": p[0], "current": p[1], "new": p[3], "security": False})
    elif mgr == "apk":
        res["installed_count"] = len(run(["apk", "info"])[1].splitlines())
        if upgradable:
            for line in run(["apk", "list", "-u"], timeout=60)[1].splitlines():
                p = line.split()
                if p:
                    res["upgradable"].append({"name": p[0], "security": False})
    elif mgr == "zypper":
        res["installed_count"] = len(run(["rpm", "-qa"], timeout=60)[1].splitlines())
        if upgradable:
            for line in run(["zypper", "-q", "lu"], timeout=120)[1].splitlines():
                p = [x.strip() for x in line.split("|")]
                if len(p) >= 5 and p[0] in ("v", ""):
                    res["upgradable"].append({"name": p[2], "current": p[3], "new": p[4], "security": False})
    res["upgradable_count"] = len(res["upgradable"])
    res["security_count"] = len(res["security"])
    return res


def _mtime(path):
    try:
        from ..utils import human_time
        return human_time(os.stat(path).st_mtime)
    except OSError:
        return None


def package_search(name: str) -> list[dict]:
    mgr = _pkg_manager()
    if mgr == "apt":
        out = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n", f"*{name}*"], timeout=30)[1]
        return [dict(zip(("name", "version", "status"), l.split("\t"))) for l in out.splitlines() if l]
    if mgr in ("dnf", "yum", "zypper"):
        out = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n", f"*{name}*"], timeout=30)[1]
        return [dict(zip(("name", "version"), l.split("\t"))) for l in out.splitlines() if l]
    if mgr == "pacman":
        out = run(["pacman", "-Qs", name])[1]
        return [{"name": l.split()[0], "version": l.split()[1]} for l in out.splitlines() if l.startswith("local/")]
    return []


def package_upgrade(names: list[str] | None = None, security_only: bool = False, actor: str = "cli") -> dict:
    mgr = _pkg_manager()
    if security_only and mgr not in ("apt", "dnf", "yum"):
        return {"ok": False, "error": f"{mgr or 'unknown'} 不支持仅安全更新，已拒绝执行"}
    if names and any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.:@-]*", name) for name in names):
        return {"ok": False, "error": "invalid package name"}
    if mgr == "apt":
        rc, out, err = run(["apt-get", "update"], timeout=300)
        if rc:
            return audit_result("package.upgrade", {"ok": False, "stage": "update",
                                "error": err.strip() or out.strip() or "apt-get update failed"}, actor)
        if security_only:
            available = packages()
            if available.get("error"):
                return audit_result("package.upgrade", {"ok": False, "stage": "check", "error": available["error"]}, actor)
            pk = [p["name"] for p in available["security"] if not names or p["name"] in names]
            if not pk:
                return audit_result("package.upgrade", {"ok": True, "skipped": True,
                                    "output": "没有符合条件的安全更新"}, actor)
            cmd = ["apt-get", "install", "-y", "--only-upgrade", *pk]
        elif names:
            cmd = ["apt-get", "install", "-y", "--only-upgrade", *names]
        else:
            cmd = ["apt-get", "upgrade", "-y"]
    elif mgr in ("dnf", "yum"):
        cmd = [mgr, "-y", "upgrade", *(names or [])] + (["--security"] if security_only else [])
    elif mgr == "pacman":
        cmd = ["pacman", "-Syu", "--noconfirm"] + (names or [])
    elif mgr == "apk":
        cmd = ["apk", "upgrade"] + (names or [])
    else:
        return {"ok": False, "error": "unsupported package manager"}
    rc, out, err = run(cmd, timeout=1800, env={"DEBIAN_FRONTEND": "noninteractive"})
    return audit_result("package.upgrade", {"ok": rc == 0, "command": " ".join(cmd), "output": (out + err)[-5000:]}, actor)


# ---------------------------------------------------------------- Docker
def _docker_json_lines(args: list[str], timeout=30) -> list[dict]:
    rc, out, err = run(["docker", *args, "--format", "{{json .}}"], timeout=timeout)
    if rc != 0:
        return []
    res = []
    for line in out.splitlines():
        try:
            res.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return res


def docker_info() -> dict:
    if not which("docker"):
        return {"available": False, "note": "docker 未安装"}
    rc, out, err = run(["docker", "info", "--format", "{{json .}}"], timeout=20)
    if rc != 0:
        return {"available": False, "note": err.strip()[:300] or "docker daemon 不可用或无权限（需加入 docker 组）"}
    try:
        info = json.loads(out)
    except json.JSONDecodeError:
        info = {}
    containers = _docker_json_lines(["ps", "-a"])
    stats = {s.get("Name"): s for s in _docker_json_lines(["stats", "--no-stream"])}
    for c in containers:
        s = stats.get(c.get("Names"))
        if s:
            c["cpu"] = s.get("CPUPerc")
            c["mem"] = s.get("MemUsage")
            c["net"] = s.get("NetIO")
    images = _docker_json_lines(["images"])
    dangling = [i for i in images if i.get("Repository") == "<none>"]
    volumes = _docker_json_lines(["volume", "ls"])
    networks = _docker_json_lines(["network", "ls"])
    df = _docker_json_lines(["system", "df"])
    # 暴露端口检查
    exposed = []
    for c in containers:
        for m in re.finditer(r"(?:0\.0\.0\.0|\[?::\]?):(\d+)->(\d+)/(\w+)", c.get("Ports", "")):
            exposed.append({"container": c.get("Names"), "host_port": int(m.group(1)), "container_port": int(m.group(2)), "proto": m.group(3)})
    return {
        "available": True, "version": info.get("ServerVersion"), "root_dir": info.get("DockerRootDir"),
        "containers": containers, "running": sum(1 for c in containers if c.get("State") == "running"),
        "images": images, "dangling_images": len(dangling), "volumes": volumes, "networks": networks, "disk": df,
        "exposed_ports": exposed,
        "warnings": ([{"level": "medium", "msg": f"{len(dangling)} 个悬空镜像可清理"}] if dangling else []) +
                    ([{"level": "medium", "msg": "有容器端口绑定到 0.0.0.0，docker 会绕过 ufw/firewalld 规则直接暴露"}] if exposed else []),
    }


def docker_action(target: str, action: str, name: str, actor: str = "cli") -> dict:
    allowed = {"container": {"start", "stop", "restart", "rm", "logs"}, "image": {"rm"}, "volume": {"rm"}}
    if action not in allowed.get(target, set()):
        return {"ok": False, "error": f"不支持的操作 {target}/{action}"}
    if not re.match(r"^[\w.:/-]+$", name):
        return {"ok": False, "error": "invalid name"}
    if target == "container" and action == "logs":
        rc, out, err = run(["docker", "logs", "--tail", "200", name], timeout=30)
        return {"ok": rc == 0, "output": (out + err)[-20000:]}
    cmd = ["docker", target if target != "container" else "container", action, name]
    rc, out, err = run(cmd, timeout=120)
    return audit_result("docker", {"ok": rc == 0, "command": " ".join(cmd), "output": (out + err).strip()}, actor)


def docker_prune(volumes: bool = False, actor: str = "cli") -> dict:
    cmd = ["docker", "system", "prune", "-f"] + (["--volumes"] if volumes else [])
    rc, out, err = run(cmd, timeout=600)
    return audit_result("docker.prune", {"ok": rc == 0, "volumes": volumes, "output": (out + err).strip()[-3000:]}, actor)


# ---------------------------------------------------------------- 依赖漏洞扫描（OSV）
def _parse_requirements(path: str) -> list[tuple[str, str]]:
    deps = []
    for line in read_lines(path):
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*==\s*([\w.+-]+)", line)
        if m:
            deps.append((re.sub(r"\[.*\]", "", m.group(1)).lower(), m.group(2)))
    return deps


def _parse_package_lock(path: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(read_text(path))
    except json.JSONDecodeError:
        return []
    deps = []
    for k, v in data.get("packages", {}).items():
        if k and v.get("version"):
            deps.append((k.split("node_modules/")[-1], v["version"]))
    if not deps:
        for k, v in data.get("dependencies", {}).items():
            if v.get("version"):
                deps.append((k, v["version"]))
    return deps


def _osv_query(queries: list[dict], timeout: int = 60) -> list[dict]:
    """批量查询 OSV（需外网）。"""
    results = []
    for i in range(0, len(queries), 500):
        body = json.dumps({"queries": queries[i:i + 500]}).encode()
        req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            results += json.loads(resp.read()).get("results", [])
    return results


def dependency_scan(paths: list[str] | None = None, online: bool = True) -> dict:
    """扫描 requirements.txt / package-lock.json / venv 已装包，查询 OSV 漏洞库。"""
    targets = []
    if paths:
        for p in paths:
            if os.path.isdir(p) and os.path.exists(os.path.join(p, "pyvenv.cfg")):
                targets.append(("venv", p))
            elif os.path.isfile(p):
                targets.append(("file", p))
    else:
        roots = [r for r in SCAN_ROOTS if os.path.isdir(r)]
        targets += [("file", os.path.join(d, "requirements.txt")) for d in _walk_find("requirements.txt", roots, 4)]
        targets += [("file", os.path.join(d, "package-lock.json")) for d in _walk_find("package-lock.json", roots, 4)]
    manifests, queries, index = [], [], []
    for kind, p in targets:
        if kind == "venv":
            deps = [(x["name"].lower(), x["version"]) for x in env_packages(p)]
            eco = "PyPI"
        elif p.endswith("package-lock.json"):
            deps, eco = _parse_package_lock(p), "npm"
        else:
            deps, eco = _parse_requirements(p), "PyPI"
        manifests.append({"path": p, "ecosystem": eco, "dependencies": len(deps)})
        for name, ver in deps:
            queries.append({"package": {"name": name, "ecosystem": eco}, "version": ver})
            index.append((p, name, ver))
    vulns, error = [], ""
    if online and queries:
        try:
            for (p, name, ver), r in zip(index, _osv_query(queries)):
                for v in r.get("vulns", []):
                    vulns.append({"manifest": p, "package": name, "version": ver, "id": v.get("id"),
                                  "summary": v.get("summary", "")[:200], "modified": v.get("modified")})
        except Exception as e:  # 网络不可用
            error = f"OSV 查询失败: {e}"
    # 本地 pip-audit 作为补充
    local_tools = {t: bool(which(t)) for t in ("pip-audit", "npm", "trivy", "grype")}
    return {"manifests": manifests, "total_dependencies": len(queries), "vulnerabilities": vulns,
            "vulnerable_count": len({(v['package'], v['version']) for v in vulns}), "error": error, "local_tools": local_tools}


# ---------------------------------------------------------------- 开发环境树
def _node(label: str, note: str | None = None, children: list | None = None, **extra) -> dict:
    n = {"label": label, "note": note or "", "children": children or []}
    n.update(extra)
    return n


def _ver(cmd: list[str], pattern: str = r"(\d+(?:\.\d+)+)", timeout: int = 10) -> str:
    rc, out, err = run(cmd, timeout=timeout)
    m = re.search(pattern, out + err)
    return m.group(1) if m else ((out + err).strip().splitlines() or [""])[0][:40]


def _tool_versions(tools: dict[str, list[str]]) -> list[dict]:
    """tools: 名称 -> 版本命令。只返回已安装的。"""
    out = []
    for name, cmd in tools.items():
        exe = which(cmd[0])
        if exe:
            out.append(_node(f"{name} {_ver(cmd)}", exe, kind="tool", name=name, path=exe))
    return out


def _conda_root(conda_exe: str) -> str:
    return os.path.dirname(os.path.dirname(os.path.realpath(conda_exe)))


def _python_tree(include_size: bool, with_packages: int) -> dict:
    py = python_envs(include_size=include_size)
    children = []
    # 系统解释器（补充 /usr/bin/python3.x 这类没有软链进 PATH 的版本）
    seen = {s["path"] for s in py["system"]}
    for exe in sorted(glob.glob("/usr/bin/python3.[0-9]*") + glob.glob("/usr/local/bin/python3.[0-9]*")):
        real = os.path.realpath(exe)
        if real not in seen and not exe.endswith(("-config", "m")) and os.access(exe, os.X_OK):
            seen.add(real)
            py["system"].append({"name": os.path.basename(exe), "path": real, "version": _py_version(exe)})
    sys_nodes = [_node(f"{s['name']} {s['version']}", s["path"], kind="interpreter") for s in py["system"]]
    children.append(_node(f"系统解释器 ({len(sys_nodes)})", children=sys_nodes))
    # 工具
    tool_nodes = _tool_versions({
        "pip": ["pip", "--version"], "pipx": ["pipx", "--version"], "poetry": ["poetry", "--version"],
        "pdm": ["pdm", "--version"], "uv": ["uv", "--version"], "virtualenv": ["virtualenv", "--version"],
        "pyenv": ["pyenv", "--version"], "hatch": ["hatch", "--version"],
    })
    if tool_nodes:
        children.append(_node(f"包/环境工具 ({len(tool_nodes)})", children=tool_nodes))
    # pyenv
    by_owner = {}
    for v in py["pyenv"]:
        by_owner.setdefault(v["owner"], []).append(v)
    for owner, vs in by_owner.items():
        root = os.path.dirname(os.path.dirname(vs[0]["path"]))
        global_ver = read_text(os.path.join(root, "version")).strip()
        children.append(_node(f"pyenv ({owner})", root, [
            _node(v["python"] + ("  ← global" if v["python"] == global_ver else ""), v["path"], kind="pyenv") for v in vs]))
    # conda
    conda = which("conda") or next(iter(glob.glob("/opt/*conda*/bin/conda") + glob.glob("/home/*/*conda*/bin/conda")
                                        + glob.glob("/root/*conda*/bin/conda")), None)
    if conda:
        cver = _ver([conda, "--version"])
        env_nodes = []
        for e in py["conda"]:
            name = "base" if os.path.realpath(e["path"]) == os.path.realpath(_conda_root(conda)) else os.path.basename(e["path"])
            note = " · ".join(filter(None, [f"python {e['python']}" if e["python"] else "", f"{e['packages']} 包", e["size"] or ""]))
            env_nodes.append(_node(name, f"{e['path']}  {note}", _pkg_nodes(e["path"], with_packages), kind="conda", path=e["path"]))
        children.append(_node(f"conda {cver} ({len(env_nodes)} 个环境)", _conda_root(conda), env_nodes))
    # venv
    venv_nodes = []
    for v in py["venvs"]:
        note = " · ".join(filter(None, [f"python {v['python']}" if v["python"] else "", f"{v['packages']} 包",
                                        v["size"] or "", f"owner {v['owner']}", "" if v["has_pip"] else "无 pip"]))
        venv_nodes.append(_node(v["path"], note, _pkg_nodes(v["path"], with_packages), kind="venv", path=v["path"], base=v["base"]))
    children.append(_node(f"venv ({len(venv_nodes)})", "扫描: " + ", ".join(py["scanned_roots"][:6]) + (" …" if len(py["scanned_roots"]) > 6 else ""), venv_nodes))
    head = py["system"][0]["version"] if py["system"] else "未安装"
    return _node(f"Python {head}", f"{len(py['system'])} 个解释器 · {len(py['venvs'])} venv · {len(py['conda'])} conda · {len(py['pyenv'])} pyenv", children)


def _pkg_nodes(env_path: str, limit: int) -> list[dict]:
    if limit <= 0:
        return []
    pk = env_packages(env_path)
    nodes = [_node(f"{p['name']} {p['version']}", kind="package") for p in pk[:limit]]
    if len(pk) > limit:
        nodes.append(_node(f"… 其余 {len(pk) - limit} 个"))
    return nodes


def _node_tree() -> dict | None:
    d = node_envs()
    if not d["system"] and not d["versions"]:
        return None
    children = []
    sys_nodes = [_node(f"{k} {v['version'].lstrip('v')}", v["path"], kind="tool") for k, v in d["system"].items()]
    if sys_nodes:
        children.append(_node(f"系统 ({len(sys_nodes)})", children=sys_nodes))
    by_mgr = {}
    for v in d["versions"]:
        by_mgr.setdefault((v.get("manager", "nvm"), v["user"]), []).append(v)
    for (mgr, user), vs in by_mgr.items():
        root = os.path.dirname(os.path.dirname(os.path.dirname(vs[0]["path"]))) if mgr == "nvm" else os.path.dirname(os.path.dirname(vs[0]["path"]))
        default = read_text(os.path.join(root, "alias", "default")).strip() if mgr == "nvm" else ""
        children.append(_node(f"{mgr} ({user})", root, [
            _node(v["version"] + ("  ← default" if default and v["version"].lstrip("v").startswith(default.lstrip("v")) else ""), v["path"], kind=mgr) for v in vs]))
    if d["global_packages"]:
        children.append(_node(f"npm 全局包 ({len(d['global_packages'])})", children=[
            _node(f"{p['name']} {p['version']}", kind="package") for p in d["global_packages"]]))
    if d["projects"]:
        children.append(_node(f"项目 package.json ({len(d['projects'])})", children=[
            _node(p["path"], "已安装 node_modules" if p["has_node_modules"] else "未安装依赖", kind="project") for p in d["projects"][:20]]
            + ([_node(f"… 其余 {len(d['projects']) - 20} 个")] if len(d["projects"]) > 20 else [])))
    head = d["system"].get("node", {}).get("version", "").lstrip("v") or f"{len(d['versions'])} 个版本(nvm)"
    return _node(f"Node.js {head}", children=children)


def _java_tree(other: dict) -> dict | None:
    rt = other["runtimes"]
    jvms = sorted(p for p in glob.glob("/usr/lib/jvm/*") if os.path.isdir(p) and not os.path.islink(p))
    sdk = [m for m in other["managers"].get("sdkman", []) if "/candidates/java/" in m["path"]]
    if "java" not in rt and not jvms and not sdk:
        return None
    children = []
    if "java" in rt:
        children.append(_node(f"java {rt['java']['version']}", os.path.realpath(rt["java"]["path"]), kind="tool"))
    if "javac" in rt:
        children.append(_node(f"javac {rt['javac']['version']}", rt["javac"]["path"], kind="tool"))
    for t in _tool_versions({"maven": ["mvn", "--version"], "gradle": ["gradle", "--version"]}):
        children.append(t)
    if os.environ.get("JAVA_HOME"):
        children.append(_node("JAVA_HOME", os.environ["JAVA_HOME"]))
    if jvms:
        children.append(_node(f"/usr/lib/jvm ({len(jvms)})", children=[_node(os.path.basename(j), kind="jdk") for j in jvms]))
    _manager_nodes(children, sdk, "sdkman", lambda p: os.path.basename(p))
    return _node(f"Java {rt.get('java', {}).get('version', '')}".rstrip(), children=children)


def _manager_nodes(children: list, items: list[dict], mgr: str, label):
    by_user = {}
    for it in items:
        by_user.setdefault(it["user"], []).append(it)
    for user, its in by_user.items():
        children.append(_node(f"{mgr} ({user})", children=[_node(label(i["path"]), i["path"], kind=mgr) for i in its]))


def _simple_lang(other: dict, title: str, runtimes: list[str], managers: dict[str, str], extra: list[dict] | None = None) -> dict | None:
    rt = other["runtimes"]
    found = [r for r in runtimes if r in rt]
    mgr_items = {m: other["managers"].get(m, []) for m in managers if other["managers"].get(m)}
    if not found and not mgr_items:
        return None
    children = [_node(f"{r} {rt[r]['version']}", rt[r]["path"], kind="tool") for r in found] + (extra or [])
    for m, items in mgr_items.items():
        _manager_nodes(children, items, m, lambda p, m=m: os.path.basename(p) if managers[m] == "base" else p)
    head = rt[found[0]]["version"] if found else ""
    return _node(f"{title} {head}".rstrip(), children=children)


def _rust_extra() -> list[dict]:
    extra = []
    for user, home in home_dirs():
        settings = read_text(os.path.join(home, ".rustup", "settings.toml"))
        m = re.search(r'default_toolchain\s*=\s*"([^"]+)"', settings)
        if m:
            extra.append(_node(f"rustup 默认工具链 ({user})", m.group(1)))
    return extra


def _go_extra() -> list[dict]:
    extra = []
    if which("go"):
        rc, out, _ = run(["go", "env", "GOROOT", "GOPATH"], timeout=10)
        lines = out.splitlines()
        if len(lines) >= 2:
            extra.append(_node("GOROOT", lines[0]))
            extra.append(_node("GOPATH", lines[1]))
    return extra


def _docker_tree() -> dict | None:
    if not which("docker"):
        return None
    rc, out, err = run(["docker", "info", "--format", "{{json .}}"], timeout=20)
    if rc != 0:
        return _node("Docker (daemon 不可用)", err.strip()[:120] or "需 root 或加入 docker 组")
    try:
        info = json.loads(out)
    except json.JSONDecodeError:
        info = {}
    children = [
        _node(f"容器 {info.get('ContainersRunning', 0)} 运行 / {info.get('Containers', 0)} 总计"),
        _node(f"镜像 {info.get('Images', 0)} 个"),
        _node(f"存储驱动 {info.get('Driver', '?')}", info.get("DockerRootDir", "")),
    ]
    for c in _docker_json_lines(["ps", "-a"]):
        children.append(_node(f"{c.get('Names')}  [{c.get('State')}]", f"{c.get('Image')}  {c.get('Status', '')}", kind="container"))
    children += _tool_versions({"docker compose": ["docker", "compose", "version"], "podman": ["podman", "--version"]})
    return _node(f"Docker {info.get('ServerVersion', '')}", children=children)


def _syspkg_tree() -> dict | None:
    pk = packages(upgradable=False)
    if not pk["manager"]:
        return None
    children = [_node(f"已安装 {pk['installed_count']} 个包")]
    if pk.get("last_update"):
        children.append(_node("上次更新索引", pk["last_update"]))
    children.append(_node("查看可更新/安全更新: singularity env packages"))
    if which("snap"):
        snaps = [l.split()[0] for l in run(["snap", "list"], timeout=15)[1].splitlines()[1:]]
        if snaps:
            children.append(_node(f"snap ({len(snaps)})", ", ".join(snaps[:15]) + (" …" if len(snaps) > 15 else "")))
    if which("flatpak"):
        fps = run(["flatpak", "list", "--app", "--columns=application"], timeout=15)[1].splitlines()
        if fps:
            children.append(_node(f"flatpak ({len(fps)})", ", ".join(fps[:10])))
    children += _tool_versions({"brew": ["brew", "--version"], "nix": ["nix", "--version"]})
    return _node(f"系统包管理 {pk['manager']}", children=children)


def dev_tree(include_size: bool = False, with_packages: int = 0) -> dict:
    """开发环境树：语言 → 版本/管理器 → 环境。with_packages>0 时在每个 venv/conda 下列出前 N 个包。"""
    other = other_languages()
    roots = [
        _python_tree(include_size, with_packages),
        _node_tree(),
        _java_tree(other),
        _simple_lang(other, "Go", ["go"], {"gvm": "base"}, _go_extra()),
        _simple_lang(other, "Rust", ["rustc", "cargo"], {"rustup": "base"}, _rust_extra()),
        _simple_lang(other, "Ruby", ["ruby"], {"rbenv": "base", "rvm": "base"}),
        _simple_lang(other, "PHP", ["php"], {}),
        _simple_lang(other, ".NET", ["dotnet"], {}),
        _simple_lang(other, "Perl", ["perl"], {}),
    ]
    build = _tool_versions({"gcc": ["gcc", "--version"], "g++": ["g++", "--version"], "clang": ["clang", "--version"],
                            "make": ["make", "--version"], "cmake": ["cmake", "--version"], "git": ["git", "--version"]})
    if build:
        roots.append(_node("构建工具", children=build))
    if other["managers"].get("asdf"):
        asdf = []
        _manager_nodes(asdf, other["managers"]["asdf"], "asdf",
                       lambda p: "/".join(p.rstrip("/").split("/")[-2:]))
        roots += asdf
    roots.append(_docker_tree())
    roots.append(_syspkg_tree())
    roots = [r for r in roots if r]
    import platform
    host = f"{platform.node()}  {_distro()}  kernel {platform.release()}"
    return _node("开发环境", host, roots)


def _distro() -> str:
    info = {}
    for line in read_lines("/etc/os-release"):
        if "=" in line:
            k, v = line.split("=", 1)
            info[k] = v.strip('"')
    return info.get("PRETTY_NAME", info.get("NAME", "Linux"))


def summary() -> dict:
    py = python_envs(include_size=False)
    pk = packages(upgradable=True)
    dk = None
    if which("docker"):
        rc, out, err = run(["docker", "info", "--format", "{{json .}}"], timeout=20)
        if rc == 0:
            try:
                info = json.loads(out)
                dk = {"running": info.get("ContainersRunning"), "containers": info.get("Containers")}
            except (ValueError, AttributeError):
                pass
    result = {"python_venvs": len(py["venvs"]) + len(py["conda"]), "system_python": [s["version"] for s in py["system"]][:3],
            "package_manager": pk["manager"], "upgradable": pk["upgradable_count"], "security_updates": pk["security_count"],
            "reboot_required": pk["reboot_required"],
            "docker": dk if dk is not None else "n/a"}
    if pk.get("error"):
        result["error"] = pk["error"]
    return result
