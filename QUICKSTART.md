# singularity 快速使用手册

适用版本：0.2.0。运行环境：Linux / WSL，Python 3.9 及以上。

## 1. 安装与启动

在项目根目录执行：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
singularity --version
singularity --help
```

每次重新登录服务器后，先进入项目目录，再执行 `source .venv/bin/activate`。

如果拿到的是 wheel 安装包，在已激活的虚拟环境中安装：

```bash
python -m pip install --upgrade --force-reinstall ./singularity-0.2.0-py3-none-any.whl
```

更新源码后，重新执行 `python -m pip install --upgrade --force-reinstall .`，然后检查 `singularity --version`。

普通用户可以查询部分信息；查看完整账号权限、其他用户的进程信息或系统日志时，需要 root。在项目根目录可执行：

```bash
sudo .venv/bin/singularity users
```

如果当前已经是 root，直接执行 `singularity ...` 即可。

Debian / Ubuntu / Kali 也可安装 deb 包：

```bash
sudo apt install ./singularity_0.2.0-1_all.deb
/usr/bin/singularity --version
sudo /usr/bin/singularity users
```

deb 包使用系统 Python，无需激活虚拟环境。手动构建方法见 [README 的 deb 构建说明](README.md#构建-deb-安装包)。

## 2. 先试这几条命令

| 想看什么 | 命令 |
|---|---|
| 用户、所属组和有效权限 | `singularity users` |
| 开发语言、版本和虚拟环境 | `singularity env` |
| 监听端口及对应进程 | `singularity net ports` |
| 内存占用最高的 15 个进程 | `singularity proc list --sort mem --limit 15` |
| 最近 24 小时日志异常 | `singularity log anomalies --hours 24` |
| 五个模块的汇总数据 | `singularity overview` |

`users` 和 `env` 默认输出树状视图；`net`、`proc`、`log` 默认输出 JSON 概览。需要摘要数据时，也可显式执行 `singularity users summary` 或 `singularity env summary`。

## 3. 账号与权限

```bash
singularity users                       # 用户 → 所属组 → 有效权限
singularity users list --all            # 包含系统账号
singularity users groups                # 按组查看成员与权限
singularity users sudo                  # 查看 sudoers 规则与风险
singularity users ssh-keys              # SSH 公钥、指纹与重复使用情况
singularity users logins --hours 48     # 最近登录与 SSH 失败来源
singularity users risks                 # 账号风险检查
singularity users perms --root /opt     # 扫描指定目录的文件权限，可能较慢
```

权限标记中，`ROOT` 表示 root 或可通过 sudo 执行任意命令；`ROOT≈` 表示 docker、disk 等具有等同 root 风险的组。普通账号默认视图隐藏系统账号，使用 `list --all` 查看完整列表。

## 4. 网络与端口

```bash
singularity net ports                   # 监听地址、端口、进程与用户
singularity net conns                   # 连接统计与远端 IP 排名
singularity net ifaces                  # 网卡与地址
singularity net bandwidth --interval 2  # 间隔 2 秒采样网卡速率
singularity net firewall                # 防火墙状态与规则
singularity net watch                   # 比较端口变化，并保存当前基线
singularity net watch --no-update       # 比较变化，保留原基线
```

`watch` 是单次检查命令。首次执行只建立基线，再次执行才报告新增、消失或进程变更；需要定期检查时，可由 cron 调用。

## 5. 进程、服务与定时任务

```bash
singularity proc list --sort cpu --limit 20
singularity proc list --search nginx
singularity proc tree --root 1
singularity proc services --failed
singularity proc service status nginx
singularity proc service logs nginx -n 100
singularity proc cron
singularity proc startup
```

服务管理依赖 systemd；未启用 systemd 的 WSL 或容器中，相关查询可能不可用。

## 6. 开发环境、系统包与 Docker

```bash
singularity env                            # 开发环境树
singularity env tree --packages 5           # 每个环境列出前 5 个包，较慢
singularity env tree --size                 # 统计环境体积，较慢
singularity env python --root /opt/myapp    # Python 明细，并追加扫描目录
singularity env packages-of /opt/myapp/.venv
singularity env outdated /opt/myapp/.venv
singularity env export /opt/myapp/.venv > requirements.txt
singularity env node
singularity env other
singularity env packages                   # 系统包与可更新项
singularity env docker                     # 容器、镜像与磁盘占用
singularity env scan /opt/myapp/requirements.txt
```

`scan` 默认联网查询 OSV 漏洞库；`--offline` 仅整理依赖清单，不进行在线漏洞查询。`export` 导出 Python 包清单，项目代码和数据需要另行备份。

## 7. 日志排查

```bash
singularity log list --top 10
singularity log read /var/log/syslog -n 200
singularity log read /var/log/syslog -n 1000 --grep nginx -C 2
singularity log read /var/log/syslog -n 1000 --level warning
singularity log search 'error|failed|panic'
singularity log journal -u nginx --since '2 hours ago' -n 200
singularity log journal -k -n 100
singularity log anomalies --hours 24
singularity log rotate
```

把 `/var/log/syslog` 和 `nginx` 替换为服务器实际的日志路径、服务名。`--grep` 使用正则表达式；`--level warning` 保留 warning 及以上级别。日志文件读取范围为 `/var/log`、`/opt`、`/srv`、`/home`、`/data`、`/app`、`/tmp`。

## 8. 修改系统的操作

以下命令会直接执行修改，不再额外询问确认。根据实际需要逐条运行，替换路径、服务名和容器名。

```bash
singularity proc service restart nginx
singularity proc service enable nginx
singularity proc kill 1234 --signal TERM
singularity net fw-rule allow 8080 --proto tcp --source 10.0.0.0/8
singularity net fw-rule delete 8080 --proto tcp --source 10.0.0.0/8
singularity env venv-create /opt/newapp/.venv --python python3 --install requests
singularity env clone /opt/myapp/.venv /opt/myapp/.venv-copy
singularity env venv-delete /opt/myapp/.venv-copy
singularity env pkg-upgrade --security
singularity env docker-action container restart myapp
```

服务、进程、防火墙和系统包操作通常需要 root。防火墙修改支持 ufw、firewalld、iptables；nftables 目前仅支持查看。`venv-delete` 会删除整个目标虚拟环境目录；`pkg-upgrade` 会实际安装更新，仅安全更新是否可用取决于系统包管理器。

修改操作的审计日志位于执行用户的 `~/.singularity/audit.log`；端口基线为同目录下的 `ports_snapshot.json`。root 与普通用户默认使用各自的数据目录，也可通过 `SINGULARITY_HOME` 指定。结果中的 `ok` 表示实际操作结果，`audit_error` 表示审计写入失败。

## 9. JSON 输出与常见问题

`--json` 放在模块名前，适合保存结果或交给脚本处理：

```bash
singularity --json net ports > ports.json
singularity --json users list --all > users.json
singularity --json env > environments.json
singularity --json overview > overview.json
```

- **提示 `singularity: command not found`**：重新激活 `.venv`，或在项目根目录执行 `.venv/bin/singularity --help`。
- **sudo 提示找不到命令**：使用 `sudo .venv/bin/singularity ...`；离开项目目录后，改用该程序的绝对路径。
- **提示必须指定 `cmd` 子命令**：先用 `singularity --version` 检查版本，重新安装当前版本。旧版可临时使用 `singularity users list`、`singularity env python`。
- **查询结果不完整或权限不足**：以 root 运行，并检查对应系统命令是否已安装。
- **不清楚某项参数**：执行 `singularity env --help`、`singularity log read --help` 等，逐级查看帮助。

安装后的命令不可用时，也可在项目根目录运行 `python -m singularity --help`，直接使用当前源码。
