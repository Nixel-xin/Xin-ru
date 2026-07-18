"""Git 泄露探测引擎

探测以下常见 .git 泄露:
- .git/HEAD — Git 仓库暴露
- .git/config — 仓库配置（可能含内网地址）
- .git/index — 暂存区（文件列表）
- .git/COMMIT_EDITMSG — 最近的提交信息
- .git/logs/HEAD — 提交历史
- .git/refs/heads/master — 分支引用

如果 .git/HEAD 可读 → 用 GitTools/GitHacker 思路下载整个仓库? → 不做（太慢+危险）
改为：解析 index 获取文件列表 → 尝试逐个读取 .git/objects/xx/xxxx
"""

import os
import httpx
from urllib.parse import urljoin

from .orchestrator import _save_file, _is_duplicate, _count_lines

# 常探测的 .git 路径
GIT_PATHS = [
    ".git/HEAD",
    ".git/config",
    ".git/index",
    ".git/refs/heads/main",
    ".git/refs/heads/master",
    ".git/logs/HEAD",
    ".git/COMMIT_EDITMSG",
    ".gitignore",
    ".gitattributes",
]

# 常见源码泄露路径
LEAK_PATHS = [
    ".env",
    ".env.local",
    ".env.production",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "webpack.config.js",
    "vite.config.js",
    "tsconfig.json",
    "Dockerfile",
    ".dockerignore",
]


async def git_leak_collect(
    targets: list[str],
    work_dir: str,
) -> list[dict]:
    """对每个 target 探测 .git 泄露"""
    results: list[dict] = []

    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        for target in targets:
            base = target.rstrip("/")

            for path in GIT_PATHS + LEAK_PATHS:
                url = f"{base}/{path}"

                try:
                    resp = await client.get(url)
                except Exception:
                    continue

                if resp.status_code != 200:
                    continue

                body = resp.text
                if len(body) < 5:
                    continue

                # 基本检查：是不是真实的 git 文件（而非 404 页面）
                if path.startswith(".git/") and not _looks_like_git_content(path, body):
                    continue

                target_dir = os.path.join(work_dir, "git_leak", _safe_domain(base))
                filename = path.replace("/", "_").replace(".", "_") + ".txt"
                filepath = _save_file(body, target_dir, filename)
                if _is_duplicate(filepath):
                    continue

                source_type = "git_leak" if path.startswith(".git") else "backend_file"

                results.append({
                    "source_type": source_type,
                    "url": url,
                    "local_path": filepath,
                    "file_name": filename,
                    "file_size": len(body.encode()),
                    "line_count": _count_lines(filepath),
                })

            print(f"[git_leak] {base}: 发现 {len(results)} 个泄露文件")

    return results


def _looks_like_git_content(path: str, content: str) -> bool:
    """判断内容是否真的像 git 文件（vs 404 页面）"""
    checks = {
        ".git/HEAD": lambda c: c.startswith("ref:") or len(c) == 41,
        ".git/config": lambda c: "[core]" in c or "[remote" in c,
        ".git/index": lambda c: len(c) > 100 and "DIRC" in c,
        ".git/logs/HEAD": lambda c: len(c) > 20,
        ".git/refs/heads/main": lambda c: len(c) == 41,
        ".git/refs/heads/master": lambda c: len(c) == 41,
        ".git/COMMIT_EDITMSG": lambda c: len(c) > 5,
        ".gitignore": lambda c: "node_modules" in c or "/dist" in c or "/build" in c,
        ".gitattributes": lambda c: "*" in c,
    }

    checker = checks.get(path)
    if checker:
        return checker(content)

    # 对于未明确列出的路径，检查不像是 HTML 404 页面
    if content.strip().startswith("<"):
        return False
    return True


def _safe_domain(url: str) -> str:
    """从 URL 提取安全的目录名"""
    from urllib.parse import urlparse
    netloc = urlparse(url).netloc
    return netloc.replace(":", "_").replace("/", "_")
