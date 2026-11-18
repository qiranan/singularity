#!/usr/bin/env python3
"""Build a standalone .deb with Python's standard library and dpkg-deb."""
from __future__ import annotations

import argparse
import ast
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent


def version() -> str:
    tree = ast.parse((ROOT / "singularity/__init__.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if isinstance(value, str) and re.fullmatch(r"[0-9][0-9A-Za-z.+~]*", value):
                return value
    raise ValueError("Cannot read a Debian-compatible __version__")


def write(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def main() -> int:
    parser = argparse.ArgumentParser(description="构建 singularity 的 deb 安装包（需 Linux、dpkg-deb）")
    parser.add_argument("--maintainer", default=os.environ.get("DEB_MAINTAINER", "Local Builder <builder@localhost>"),
                        help="维护者，例如 'Your Name <you@example.com>'；默认使用本地构建身份")
    parser.add_argument("--revision", default="1", help="Debian 打包修订号，默认 1")
    parser.add_argument("--output-dir", type=Path, help="输出目录，默认 dist/<版本>")
    args = parser.parse_args()
    if sys.platform != "linux" or not shutil.which("dpkg-deb"):
        parser.error("请在 Linux / WSL 中运行，并安装 dpkg")
    if not re.fullmatch(r"[^<>\r\n]+ <[^<>\s@]+@[^<>\s@]+>", args.maintainer):
        parser.error("--maintainer 格式应为 'Your Name <you@example.com>'")
    if not re.fullmatch(r"[1-9][0-9]*", args.revision):
        parser.error("--revision 必须是正整数")

    upstream = version()
    package_version = f"{upstream}-{args.revision}"
    output = (args.output_dir or ROOT / "dist" / upstream).resolve()
    output.mkdir(parents=True, exist_ok=True)
    deb = output / f"singularity_{package_version}_all.deb"

    with tempfile.TemporaryDirectory(prefix="singularity-deb-") as temporary:
        stage = Path(temporary)
        stage.chmod(0o755)
        for source in sorted((ROOT / "singularity").rglob("*.py")):
            target = stage / "usr/share/singularity" / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

        for name in ("README.md", "QUICKSTART.md"):
            write(stage / "usr/share/doc/singularity" / name, (ROOT / name).read_text(encoding="utf-8"))
        if (ROOT / "LICENSE").is_file():
            write(stage / "usr/share/doc/singularity/copyright", (ROOT / "LICENSE").read_text(encoding="utf-8"))

        write(stage / "usr/bin/singularity", """#!/usr/bin/python3 -I
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "share" / "singularity"))
from singularity.cli import main

raise SystemExit(main())
""", 0o755)
        write(stage / "DEBIAN/postinst", """#!/bin/sh
set -e
if [ "$1" = configure ]; then
    py3compile /usr/share/singularity
fi
""", 0o755)
        write(stage / "DEBIAN/prerm", """#!/bin/sh
set -e
case "$1" in
    remove|upgrade|deconfigure) py3clean /usr/share/singularity ;;
esac
""", 0o755)

        files = sorted(path for path in (stage / "usr").rglob("*") if path.is_file())
        size = (sum(path.stat().st_size for path in files) + 1023) // 1024
        write(stage / "DEBIAN/control", f"""Package: singularity
Version: {package_version}
Section: admin
Priority: optional
Architecture: all
Maintainer: {args.maintainer}
Depends: python3 (>= 3.9)
Recommends: iproute2, procps, python3-venv, ca-certificates
Installed-Size: {size}
Description: Command-line administration tool for a single Linux server
 Inspect accounts, permissions, network ports, processes, services,
 development environments and logs using Python's standard library.
""")
        write(stage / "DEBIAN/md5sums", "".join(
            f"{hashlib.md5(path.read_bytes()).hexdigest()}  {path.relative_to(stage).as_posix()}\n"
            for path in files
        ))
        for path in stage.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)
            elif path not in (stage / "usr/bin/singularity", stage / "DEBIAN/postinst", stage / "DEBIAN/prerm"):
                path.chmod(0o644)

        subprocess.run(["dpkg-deb", "--root-owner-group", "-Zxz", "--build", str(stage), str(deb)], check=True)

    checksum = hashlib.sha256(deb.read_bytes()).hexdigest()
    write(deb.with_suffix(".deb.sha256"), f"{checksum}  {deb.name}\n")
    print(f"Built: {deb}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
