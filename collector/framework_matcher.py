"""开源框架指纹识别 + GitHub 参考源码拉取

从已收集的 JS 文件中识别:
- 若依 (RuoYi) — ruoyi 关键字
- JeecgBoot — jeecg 关键字
- Element UI / Ant Design — 前端 UI 库
- Vue / React — 框架识别
- 各种后端框架的 JS 特征

识别后从 GitHub API 拉取对应版本的参考源码（如果仓库公开），
用于后续审计中的调用链对照分析。
"""

import os
import re
import json

from .orchestrator import _save_file, _is_duplicate, _count_lines

# 框架特征库: (名称, github_repo, js中识别关键字, 版本提取正则)
FRAMEWORK_FINGERPRINTS = [
    # 后端框架（前端 JS 里有特征）
    {
        "name": "RuoYi",
        "github_repo": "yangzongzhuan/RuoYi",
        "keywords": ["ruoyi", "ry-", "ruo-yi", "RuoYi"],
        "version_re": r"""(?:ruoyi|RuoYi).*?version["\s:=]+([\d.]+)""",
    },
    {
        "name": "RuoYi-Vue",
        "github_repo": "yangzongzhuan/RuoYi-Vue",
        "keywords": ["ruoyi-vue", "ruo-yi-vue", "RuoYiVue"],
        "version_re": r"""version["\s:=]+([\d.]+)""",
    },
    {
        "name": "JeecgBoot",
        "github_repo": "jeecgboot/jeecg-boot",
        "keywords": ["jeecg", "jeecg-boot", "JeecgBoot"],
        "version_re": r"""version["\s:=]+([\d.]+)""",
    },
    {
        "name": "SpringBoot-Admin",
        "github_repo": "codecentric/spring-boot-admin",
        "keywords": ["spring-boot-admin", "SpringBootAdmin"],
        "version_re": r"""version["\s:=]+([\d.]+)""",
    },
    {
        "name": "Layui",
        "github_repo": "layui/layui",
        "keywords": ["layui", "layui.all"],
        "version_re": r"""layui\.v\s*=\s*["']([\d.]+)["']""",
    },
    {
        "name": "Ant-Design-Pro",
        "github_repo": "ant-design/ant-design-pro",
        "keywords": ["ant-design-pro", "antd-pro", "AntDesignPro"],
        "version_re": r"""version["\s:=]+([\d.]+)""",
    },
    {
        "name": "Vben-Admin",
        "github_repo": "vbenjs/vben",
        "keywords": ["vben", "vben-admin"],
        "version_re": r"""version["\s:=]+([\d.]+)""",
    },
    # 前端框架
    {
        "name": "Vue",
        "github_repo": "vuejs/core",
        "keywords": ["vue.js", "vue.min", "Vue ", "Vue("],
        "version_re": r"""Vue\.version\s*=\s*["']([\d.]+)["']""",
    },
    {
        "name": "React",
        "github_repo": "facebook/react",
        "keywords": ["react.production", "react.development", "React.createElement"],
        "version_re": r"""React\s+version\s+["']?([\d.]+)""",
    },
    {
        "name": "Angular",
        "github_repo": "angular/angular",
        "keywords": ["@angular/core", "angular.min"],
        "version_re": r"""version["\s:=]+([\d.]+)""",
    },
    {
        "name": "Element-UI",
        "github_repo": "ElemeFE/element",
        "keywords": ["element-ui", "elment-ui", "ElementUI"],
        "version_re": r"""version["\s:=]+([\d.]+)""",
    },
    {
        "name": "Bootstrap",
        "github_repo": "twbs/bootstrap",
        "keywords": ["bootstrap.min", "Bootstrap "],
        "version_re": r"""Bootstrap\s+v?([\d.]+)""",
    },
    {
        "name": "jQuery",
        "github_repo": "jquery/jquery",
        "keywords": ["jquery.min", "jQuery v"],
        "version_re": r"""jQuery\s+v?([\d.]+)""",
    },
    {
        "name": "Axios",
        "github_repo": "axios/axios",
        "keywords": ["axios.min", "axios/"],
        "version_re": r"""version["\s:=]+([\d.]+)""",
    },
    {
        "name": "微信小程序",
        "github_repo": None,  # 不是开源框架，但需要标记
        "keywords": ["wx.request", "wx.login", "wx.getStorageSync", "App({", "Page({", "Component({"],
        "version_re": None,
    },
    {
        "name": "UniApp",
        "github_repo": "dcloudio/uni-app",
        "keywords": ["uni.request", "uni.login", "uni-app"],
        "version_re": None,
    },
]

# GitHub 缓存目录（依赖少时直接用 httpx 拉，不走 git clone）
GITHUB_RAW = "https://raw.githubusercontent.com"


async def framework_collect(
    targets: list[str],
    work_dir: str,
    collected_files: list[dict],
) -> list[dict]:
    """
    扫描已收集的 JS 文件，识别开源框架并拉取参考源码。
    对于安全审计来说，知道后端用什么框架（如 RuoYi）是有价值的——
    可以对照 GitHub 源码找出路由、参数校验、签名逻辑的漏洞。
    """
    results: list[dict] = []
    detected_frameworks: set[str] = set()

    # 扫描所有 JS 文件
    for f in collected_files:
        if f["source_type"] not in ("js_bundle", "spider", "path_brute", "sourcemap_restored"):
            continue

        try:
            with open(f["local_path"], "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read(50000)  # 只读前面 50KB
        except Exception:
            continue

        for fp in FRAMEWORK_FINGERPRINTS:
            name = fp["name"]
            if name in detected_frameworks:
                continue  # 已经识别过了

            # 检查关键词
            matched = any(kw.lower() in content.lower() for kw in fp["keywords"])
            if not matched:
                continue

            detected_frameworks.add(name)

            # 尝试提取版本
            version = "unknown"
            if fp["version_re"]:
                match = re.search(fp["version_re"], content, re.IGNORECASE)
                if match:
                    version = match.group(1)

            # 如果有 GitHub 仓库，尝试拉取关键文件
            if fp["github_repo"]:
                ref_files = await _fetch_github_refs(
                    fp["github_repo"],
                    work_dir,
                    name,
                )
                for ref_file in ref_files:
                    results.append(ref_file)

            # 🔴 框架本身不是源码文件，不加入 collected_files 列表
            # 框架信息写入一个单独的 JSON 摘要文件
            summary_path = os.path.join(work_dir, "framework_refs", f"{name}_v{version}_summary.json")
            os.makedirs(os.path.dirname(summary_path), exist_ok=True)
            with open(summary_path, "w", encoding="utf-8") as sf:
                json.dump({
                    "name": name,
                    "version": version,
                    "github_repo": fp.get("github_repo"),
                    "detected_keywords": [kw for kw in fp["keywords"] if kw.lower() in content.lower()],
                }, sf, ensure_ascii=False)

            print(f"[framework] ✅ 识别到框架: {name} v{version} -> {fp.get('github_repo', 'N/A')}")

    print(f"[framework] 收集完成: {len(detected_frameworks)} 个框架, 共 {len(results)} 个文件")
    return results


async def _fetch_github_refs(
    repo: str,
    work_dir: str,
    framework_name: str,
) -> list[dict]:
    """
    从 GitHub raw 拉取框架的关键参考文件。

    对于一个识别的框架，不需要拉整个仓库——只需拉关键文件：
    - 安全配置类 (SecurityConfig, ShiroConfig 等)
    - 控制器示例
    - 过滤器/拦截器
    - 签名/加密工具类
    """
    import httpx

    # 关键文件路径（相对于仓库根目录）
    KEY_FILES = [
        # Java/Spring Boot 常见安全文件
        "src/main/java/com/ruoyi/framework/config/ShiroConfig.java",
        "src/main/java/com/ruoyi/framework/config/SecurityConfig.java",
        "src/main/java/com/ruoyi/framework/web/service/TokenService.java",
        "src/main/java/com/ruoyi/framework/interceptor/RepeatSubmitInterceptor.java",
        "src/main/java/com/ruoyi/common/filter/XssFilter.java",
        "src/main/java/com/ruoyi/common/utils/ServletUtils.java",
        "src/main/java/com/ruoyi/common/utils/SecurityUtils.java",
        "src/main/java/com/ruoyi/framework/web/exception/GlobalExceptionHandler.java",
        # 通用安全文件
        "src/main/java/**/config/ShiroConfig.java",
        "src/main/java/**/config/WebSecurityConfig.java",
        "src/main/java/**/filter/**Filter.java",
        "src/main/java/**/interceptor/**Interceptor.java",
        "src/main/java/**/utils/TokenUtil.java",
        "src/main/java/**/utils/JwtUtil.java",
    ]

    results = []
    target_dir = os.path.join(work_dir, "framework_refs", framework_name)

    async with httpx.AsyncClient(timeout=10) as client:
        # 先试 master 分支，再试 main
        for branch in ["master", "main"]:
            success = False
            # 先拉 README 验证仓库可访问
            for path in KEY_FILES:
                url = f"{GITHUB_RAW}/{repo}/{branch}/{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and len(resp.text) > 20:
                        filename = path.replace("/", "_").replace("*", "any")
                        filepath = _save_file(resp.text, target_dir, filename)
                        if _is_duplicate(filepath):
                            continue
                        results.append({
                            "source_type": "framework_ref",
                            "url": url,
                            "local_path": filepath,
                            "file_name": f"{framework_name}_{filename}",
                            "file_size": len(resp.text.encode()),
                            "line_count": _count_lines(filepath),
                        })
                        success = True
                except Exception:
                    pass

            if success:
                break  # 找到有效的分支就停止

    return results
