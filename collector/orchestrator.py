"""源码收集编排器 — 协调全部 7 种收集策略，去重并持久化

调用方式:
    from collector.orchestrator import collect_all

    files = await collect_all(
        targets=["https://example.com"],
        work_dir="/app/data/collected/task_1",
        cookies={"https://example.com": "session=xxx"},
        leads=None,  # 或 [{"url": "https://新发现域名", "reason": "..."}]
    )
"""

import os
import hashlib
from dataclasses import dataclass, field
from typing import Optional

# ============================================================
# 数据结构
# ============================================================

@dataclass
class CollectedFileInfo:
    """收集到的源码文件元数据"""
    source_type: str       # js_bundle / sourcemap_restored / git_leak / backup / framework_ref / spider / yakit_export
    url: str               # 来源 URL
    local_path: str        # 本地存储的绝对路径
    file_name: str         # 文件名
    file_size: int         # 字节
    line_count: int        # 行数


# ============================================================
# 去重策略 — 用 SHA256 hash
# ============================================================
_SEEN_HASHES: set[str] = set()


def _hash_file(filepath: str) -> str:
    """计算文件 SHA256，用于去重"""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
    except Exception:
        return ""
    return h.hexdigest()


def _is_duplicate(filepath: str) -> bool:
    """检查文件是否已收集过（按内容 hash 去重）"""
    file_hash = _hash_file(filepath)
    if not file_hash:
        return True  # 读不了就跳过
    if file_hash in _SEEN_HASHES:
        return True
    _SEEN_HASHES.add(file_hash)
    return False


def _save_file(content: bytes | str, work_dir: str, filename: str) -> str:
    """保存文件到 work_dir，返回绝对路径"""
    os.makedirs(work_dir, exist_ok=True)
    filepath = os.path.join(work_dir, filename)
    if isinstance(content, str):
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        with open(filepath, "wb") as f:
            f.write(content)
    return filepath


def _count_lines(filepath: str) -> int:
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


# ============================================================
# 顶层编排器
# ============================================================

async def collect_all(
    targets: list[str],
    work_dir: str,
    cookies: dict[str, str] | None = None,
    leads: list[dict] | None = None,
    options: dict | None = None,
) -> list[dict]:
    """
    对 targets 运行全部源码收集策略，返回 CollectedFileInfo 列表。

    每个收集器都有独立超时保护 — 单个卡住不会拖垮整个 Agent
    （无人值守的关键：任何一个收集器超时就跳过，继续下一个）。

    Args:
        targets: 目标 URL 列表，如 ["https://example.com"]
        work_dir: 本地存储根目录
        cookies: target → cookie string 映射
        leads: 补充收集的线索列表，非空时表示增量补收模式

    Returns:
        list[dict] — 与 CollecctedFile 模型兼容的字典列表
    """
    import asyncio

    all_files: list[dict] = []
    cookies = cookies or {}
    options = options or {}

    # 内容哈希缓存只能在单次收集中共享，不能污染其他任务。
    clear_hash_cache()

    is_supplement = bool(leads)

    async def _run(name: str, timeout: float, coro_factory):
        """带超时保护地运行单个收集器。超时/异常都不影响其他收集器。"""
        print(f"[collector] start {name} timeout={timeout}s", flush=True)
        try:
            result = await asyncio.wait_for(coro_factory(), timeout=timeout)
            count = len(result or [])
            if result:
                all_files.extend(result)
            print(f"[collector] done {name} files=+{count} total={len(all_files)}", flush=True)
        except asyncio.TimeoutError:
            print(f"[collector] {name} 超时 ({timeout}s)，跳过", flush=True)
        except ImportError as e:
            print(f"[collector] {name} ImportError: {e}", flush=True)
        except Exception as e:
            import traceback
            print(f"[collector] {name} error: {e}\n{traceback.format_exc()[:300]}", flush=True)

    # ========================================
    # 策略 1: LLM 主导源码收集（HTTP + 模型抽资产 + 下载）
    # ========================================
    await _run("llm_source", float(options.get("llm_source_timeout", 240)), lambda: _import_and_call(
        "collector.llm_source", "llm_source_collect", targets, work_dir, cookies, options))

    # ========================================
    # 策略 2: Playwright 爬虫（补充，可关）
    # ========================================
    if options.get("enable_spider", False):
        await _run("spider", float(options.get("spider_timeout", 60)), lambda: _import_and_call(
            "collector.spider", "spider_collect", targets, work_dir, cookies))

    # ========================================
    # 策略 3: sourcemap 发现 + 还原
    # ========================================
    if options.get("enable_sourcemap", True):
        await _run("sourcemap", 45, lambda: _import_and_call(
            "collector.sourcemap", "sourcemap_collect", targets, work_dir, all_files))

    # ========================================
    # 策略 4: Git 泄露（默认关）
    # ========================================
    if not is_supplement and options.get("enable_git_leak", False):
        await _run("git_leak", 45, lambda: _import_and_call(
            "collector.git_leak", "git_leak_collect", targets, work_dir))

    # ========================================
    # 策略 5: 备份/临时文件
    # ========================================
    if options.get("enable_backup", True):
        await _run("backup", 30, lambda: _import_and_call(
            "collector.backup_detector", "backup_collect", targets, work_dir, all_files))

    # ========================================
    # 策略 6: 子域名枚举（可选）
    # ========================================
    if not is_supplement and options.get("subdomain_discovery", False):
        await _run("subdomain", 60, lambda: _import_and_call(
            "collector.subdomain", "subdomain_collect", targets, work_dir))

    # ========================================
    # 策略 7: 路径爆破（可选）
    # ========================================
    if options.get("path_brute", False):
        await _run("path_brute", 60, lambda: _import_and_call(
            "collector.path_brute", "path_brute_collect", targets, work_dir, all_files))

    # ========================================
    # 策略 8: 框架指纹（默认关）
    # ========================================
    if not is_supplement and options.get("enable_framework", False):
        await _run("framework", 45, lambda: _import_and_call(
            "collector.framework_matcher", "framework_collect", targets, work_dir, all_files))

    # ========================================
    # 去重后返回
    # ========================================
    return [f for f in all_files if f]  # 过滤 None


async def _import_and_call(module_path: str, func_name: str, *args, **kwargs):
    """动态导入收集器并调用（延迟导入，避免某个收集器依赖缺失影响整体）。"""
    import importlib
    mod = importlib.import_module(module_path)
    func = getattr(mod, func_name)
    return await func(*args, **kwargs)


def clear_hash_cache():
    """清空去重 hash 缓存（用于补收上下文）"""
    _SEEN_HASHES.clear()
