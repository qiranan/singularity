# singularity

从 0 掌控整台 Linux 服务器：账号权限、网络端口、进程服务、软件环境、日志，一个命令看清全貌，纯命令行。

采集逻辑仅依赖 Python 标准库，直接读取 `/proc`、`/etc` 并调用系统命令。运行环境：Linux / WSL、Python 3.9+。

初次使用请看 [快速使用手册](QUICKSTART.md)，包含安装、日常查询、系统操作与常见问题。

| 模块 | 命令 | 功能 |
|---|---|---|
| 账号与权限 | `users` | **用户 → 组 → 权限** 树、**组 → 成员** 树、sudo 审计、SSH 公钥、登录审计、风险与文件权限检查 |
| 网络与端口 | `net` | 监听端口与进程、连接统计、防火墙、端口变化告警、网卡带宽 |
| 进程与服务 | `proc` | 进程、systemd 服务、cron / timers、开机启动项 |
| 软件与环境 | `env` | **开发环境树**（语言 → 版本/管理器 → 虚拟环境）、venv 管理、系统包、Docker、依赖漏洞扫描 |
| 日志 | `log` | 日志文件读取与搜索、journal、logrotate 检查、异常聚合 |

## 安装

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
singularity --help
```

不安装也可直接 `python -m singularity ...`。多数系统查询需要 root 才能看全（shadow、sudoers、其他用户的 crontab、系统日志）：`sudo .venv/bin/singularity users`。

任何命令加 `--json` 输出原始数据，便于脚本处理。

## 账号与权限

```bash
sudo singularity users              # 用户 → 组 → 有效权限（默认视图，隐藏系统账号）
sudo singularity users list --all   # 包含系统账号
sudo singularity users groups       # 组 → 成员，附带该组授予的权限和 sudoers 规则
sudo singularity users groups --all # 包含无成员的组
sudo singularity users sudo         # sudoers 规则审计
sudo singularity users ssh-keys
sudo singularity users logins --hours 48
sudo singularity users risks
sudo singularity users perms        # SUID/SGID、全局可写文件扫描（慢）
```

`users` 视图示例：

```text
alice  uid=1000  [ROOT]
├── shell /bin/bash  home /home/alice  已设密码
├── 组 (4)
│   ├── alice (主组)
│   ├── adm  [中] 可读取 /var/log 系统日志
│   ├── sudo  [ROOT] 可通过 sudo 以 root 执行任意命令（Debian/Ubuntu）
│   └── devs
├── sudo 规则 (1)
│   └── %sudo   ALL=(ALL:ALL) ALL  来自 %sudo
└── 有效权限
    ├── [ROOT] 可通过 sudo 以 root 执行任意命令  组 sudo
    ├── [ROOT] sudo 任意命令  sudoers %sudo
    └── [中] 可读取 /var/log 系统日志  组 adm
```

权限等级：`ROOT`（root / sudo 任意命令）→ `ROOT≈`（docker、disk、lxd 等等同 root 的组）→ `高`（shadow、sudo 特定命令）→ `中`（adm、systemd-journal、staff …）→ `设备` / `服务` / `普通`。等级来源：内置常见组说明表、GID、sudoers 中直接指定用户或 `%组` 的规则。用户按最高等级排序，高权限在前。

## 软件与环境

```bash
singularity env                      # 开发环境树（默认视图）
singularity env tree --packages 5    # 每个 venv / conda 下列出前 5 个包（调用 pip，较慢）
singularity env tree --size          # 统计每个环境体积
singularity env python               # Python 环境表格明细
singularity env packages-of /opt/app/.venv
singularity env outdated /opt/app/.venv
singularity env venv-create /opt/new --python python3.12 --install requests
singularity env export /opt/app/.venv > requirements.txt
singularity env clone /opt/app/.venv /opt/app/.venv2
singularity env venv-delete /opt/old/.venv
singularity env node                 # Node 明细
singularity env other                # Java/Go/Rust/… 明细
sudo singularity env packages        # 系统包：可更新 / 安全更新
sudo singularity env pkg-upgrade --security
singularity env docker
singularity env scan /opt/app/requirements.txt   # 查询 OSV 漏洞库（联网）
```

`env` 树示例（节选）：

```text
开发环境  web-01  Ubuntu 22.04.4 LTS  kernel 5.15.0-91-generic
├── Python 3.10.12  2 个解释器 · 3 venv · 2 conda · 2 pyenv
│   ├── 系统解释器 (2)
│   │   ├── python3 3.10.12  /usr/bin/python3.10
│   │   └── python3.12 3.12.3  /usr/local/bin/python3.12
│   ├── 包/环境工具 (3)
│   │   ├── pip 24.0  /usr/bin/pip
│   │   └── uv 0.4.18  /home/alice/.local/bin/uv
│   ├── pyenv (alice)  /home/alice/.pyenv
│   │   ├── 3.11.9  ← global
│   │   └── 3.12.4
│   ├── conda 24.5.0 (2 个环境)  /opt/miniconda3
│   │   ├── base  python 3.12.4 · 312 包
│   │   └── ml    python 3.10.14 · 89 包
│   └── venv (3)
│       ├── /opt/api/.venv  python 3.10.12 · 45 包 · owner deploy
│       └── /home/alice/proj/.venv  python 3.12.3 · 12 包 · owner alice
├── Node.js 20.11.1
│   ├── 系统 (3) …
│   └── nvm (alice)  v18.19.0 / v20.11.1 ← default
├── Java 17.0.9 / Go 1.22.1 / Rust 1.77.0 …
├── Docker 26.1.3  容器 2 运行 / 3 总计
└── 系统包管理 apt  已安装 1843 个包
```

覆盖：Python（系统解释器、pip/pipx/poetry/pdm/uv、pyenv、conda、venv）、Node.js（系统、nvm/fnm、全局包、项目）、Java（/usr/lib/jvm、sdkman、maven/gradle）、Go（GOROOT/GOPATH、gvm）、Rust（rustup 工具链）、Ruby（rbenv/rvm）、PHP、.NET、Perl、asdf、构建工具（gcc/clang/make/cmake/git）、Docker/compose/podman、系统包管理器与 snap/flatpak。venv 扫描范围：`/opt /srv /var/www /home /root /app /data /workspace` 及当前目录，`env python --root 目录` 可追加。

## 其它模块

```bash
sudo singularity net ports / conns / firewall / watch / bandwidth / ifaces
sudo singularity net fw-rule allow 8080 --source 10.0.0.0/8
sudo singularity proc list --sort mem / services --failed / service restart nginx / cron / startup
sudo singularity proc kill 1234 --signal KILL
sudo singularity log list / read /var/log/syslog --level warning --grep nginx / journal -u nginx / rotate / anomalies
sudo singularity overview            # 五个模块的 JSON 概览
```

`net`、`proc`、`log` 不带子命令时输出模块概览（等价于 `summary`）。

- 写操作（kill、服务启停、防火墙、包升级、docker、venv 增删）会写入审计日志 `~/.singularity/audit.log`（`SINGULARITY_HOME` 可改），`audit_error` 单独报告审计失败，`ok` 表示实际操作结果。失败返回非零退出码。
- `net watch` 首次只建立基线；`--no-update` 仅预览。可放进 cron 做端口变化告警。
- 日志读取限制在 `/var/log /opt /srv /home /data /app /tmp`。
- 系统命令（`ss`、`systemctl`、`journalctl`、防火墙工具、包管理器、docker）按实际安装情况调用，缺失时降级或说明原因。

## 仓库结构

```text
singularity/
├── pyproject.toml
├── README.md
├── QUICKSTART.md            # 快速使用手册
├── singularity/
│   ├── __init__.py          # __version__
│   ├── __main__.py
│   ├── cli.py               # 参数解析、表格/树状渲染
│   ├── overview.py          # 多模块并行概览
│   ├── utils.py             # 命令执行、读文件、审计
│   └── collectors/          # users / network / processes / environments / logs
├── scripts/build_deb.py     # Linux / WSL 中构建 deb 安装包
└── tests/
    ├── test_parsers.py      # 用真实命令输出样本验证解析器、权限推导、环境树
    ├── test_regressions.py  # 边界与 CLI 契约
    ├── test_optimizations.py # 升级、克隆隔离、日志窗口、审计轮转、概览并行
    └── smoke_wsl.py         # Linux / WSL 集成冒烟
```

每个 collector 都是无状态函数，返回 dict/list；`cli.py` 只负责展示。加新功能 = collector 加一个函数 + `cli.py` 注册一行。

## 测试与发布

```bash
python -m unittest discover -s tests -v
python tests/smoke_wsl.py            # 需在 Linux / WSL 执行

python -m pip install build twine
python -m build --outdir dist/0.2.0
python -m twine check --strict dist/0.2.0/*.whl dist/0.2.0/*.tar.gz
```

### 构建 deb 安装包

在 Debian、Ubuntu、Kali 或相应 WSL 中，从项目根目录执行：

```bash
sudo apt-get update
sudo apt-get install -y python3 dpkg
python3 scripts/build_deb.py --maintainer 'Your Name <you@example.com>'
```

将维护者替换为自己的名字与邮箱；省略 `--maintainer` 时使用 `Local Builder <builder@localhost>`，适合本地构建。构建过程无需 root、虚拟环境或 pip；版本号自动读取 `singularity/__init__.py`。当前输出为：

```text
dist/0.2.0/singularity_0.2.0-1_all.deb
dist/0.2.0/singularity_0.2.0-1_all.deb.sha256
```

校验、检查并安装：

```bash
cd dist/0.2.0
sha256sum -c singularity_0.2.0-1_all.deb.sha256
dpkg-deb --info singularity_0.2.0-1_all.deb
dpkg-deb --contents singularity_0.2.0-1_all.deb
sudo apt install ./singularity_0.2.0-1_all.deb
/usr/bin/singularity --version
sudo /usr/bin/singularity users
```

该包使用系统 Python 3.9+，程序入口为 `/usr/bin/singularity`，代码位于 `/usr/share/singularity`，手册位于 `/usr/share/doc/singularity`。`all` 表示程序不含架构相关的二进制扩展，可用于满足依赖的 amd64、arm64 等 Debian 系系统。激活的虚拟环境可能优先匹配旧命令，使用 `/usr/bin/singularity` 可明确运行 deb 安装的版本。

同一上游版本只修改打包方式时，使用 `--revision 2` 构建 `0.2.0-2`；代码升级时更新 `__version__`。用 `sudo apt remove singularity` 卸载，用户目录内的审计日志和端口基线保留。

此脚本面向自行安装与 GitHub Releases 分发；提交 Debian 官方仓库还需补齐项目许可证及正式 Debian 源码包元数据。

打包路径和无 root 构建方式参见 [Debian Python Policy](https://www.debian.org/doc/packaging-manuals/python-policy/) 与 [dpkg-deb 手册](https://manpages.debian.org/bookworm/dpkg/dpkg-deb.1.en.html)。
