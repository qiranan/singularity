"""概览采集：并行运行各模块 summary，单个模块异常不影响其它模块。"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from .collectors import users, network, processes, environments, logs
from .utils import now_iso

MODULES = {"users": users, "network": network, "processes": processes,
           "environments": environments, "logs": logs}


def collect() -> dict:
    with ThreadPoolExecutor(max_workers=len(MODULES)) as executor:
        pending = {name: executor.submit(module.summary) for name, module in MODULES.items()}
    result = {}
    for name, future in pending.items():
        try:
            result[name] = dict(future.result(), collected_at=now_iso())
        except Exception as exc:  # 单模块失败只影响自己
            result[name] = {"error": str(exc), "collected_at": now_iso()}
    return result
