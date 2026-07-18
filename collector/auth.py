"""认证获取引擎 — 全自动登录、OCR 验证码、Cookie 管理

流程:
1. Playwright 打开目标 → 检测登录表单
2. 有凭证 → 自动填表提交 → OCR 验证码 → 提取 Cookie
3. 无凭证或登录失败 → 降级返回 failed（调用方以无认证模式继续）
4. 无需登录 → 标记 no_auth

全自动模式 (所有回调=None):
- 有凭证 + 无验证码 → 自动登录 → ✅ Cookie
- 有凭证 + OCR 能识别验证码 → 自动登录 → ✅ Cookie
- 有凭证 + OCR 失败 → 返回 failed → ⚠️ 无认证继续
- 无凭证 → 返回 failed → ⚠️ 无认证继续
- 目标无需登录 → ✅ no_auth
"""

import os
import re
import asyncio
from typing import Callable, Optional, Awaitable
from urllib.parse import urljoin, urlparse


async def acquire_auth(
    target: str,
    work_dir: str,
    credentials: str | None = None,
    on_captcha: Optional[Callable[[str], Awaitable[str]]] = None,
    on_need_credentials: Optional[Callable[[str], Awaitable[str | None]]] = None,
    on_need_cookie: Optional[Callable[[str], Awaitable[str | None]]] = None,
) -> dict:
    """
    对单个 target 尝试获取认证。

    Args:
        target: 目标 URL
        work_dir: 截图等临时文件存储目录
        credentials: "user:pass" 或 None
        on_captcha: 验证码回调，返回验证码字符串
        on_need_credentials: 需要账号密码时的回调
        on_need_cookie: 需要直接给 Cookie 时的回调

    Returns:
        {
            "success": bool,
            "cookies": "key=value; key2=value2" | None,
            "method": "form_login" | "cookie_provided" | "no_auth_needed" | "failed",
            "reason": "说明",
        }
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {
            "success": False,
            "cookies": None,
            "method": "failed",
            "reason": "Playwright 未安装",
        }

    result = {
        "success": False,
        "cookies": None,
        "method": "failed",
        "reason": "",
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"],
        )
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        )
        page = await context.new_page()

        try:
            # ---- 第 1 步：导航到目标，看是否需要登录 ----
            try:
                await page.goto(target, wait_until="load", timeout=20000)
            except Exception as e:
                result["reason"] = f"导航失败: {e}"
                await browser.close()
                return result

            await asyncio.sleep(2)

            # 检查当前是否已经在登录页面或被重定向
            current_url = page.url
            is_login_page = _detect_login_page(current_url)

            # 如果没有重定向到登录页，尝试点击登录链接 / 常见路径发现
            if not is_login_page:
                login_link = await _find_login_link(page)
                if not login_link:
                    try:
                        login_link = await discover_auth_entry(page, target, kind="login")
                    except Exception:
                        login_link = None
                if login_link:
                    try:
                        await page.goto(login_link, wait_until="load", timeout=15000)
                        await asyncio.sleep(2)
                        is_login_page = True
                    except Exception:
                        pass

            # 如果还是没找到登录页 → 可能不需要认证
            if not is_login_page:
                # 再检查是否有明显的登录表单
                has_form = await _detect_login_form(page)
                if not has_form:
                    result["success"] = True
                    result["method"] = "no_auth_needed"
                    result["cookies"] = None
                    result["reason"] = "目标无需登录即可访问"

                    # 仍然记录当前 Cookie（可能有访客 Cookie）
                    cookies = await context.cookies()
                    if cookies:
                        result["cookies"] = _format_cookies(cookies)
                    await browser.close()
                    return result

            # ---- 第 2 步：有登录页面，尝试登录 ----
            # 获取当前 cookies（用于后续请求）
            initial_cookies = await context.cookies()

            # 如果没有提供凭证，问人
            if not credentials:
                if on_need_credentials:
                    creds = await on_need_credentials(
                        f"目标 {target} 需要登录。\n当前在: {current_url}"
                    )
                    if creds and ":" in creds:
                        credentials = creds

            if credentials and ":" in credentials:
                username, _, password = credentials.partition(":")
                password = password.strip()

                # ---- 尝试自动填表登录 ----
                login_ok = await _try_form_login(page, username, password)

                if not login_ok:
                    # 检查是否有验证码
                    captcha_img = await _find_captcha(page)
                    if captcha_img:
                        captcha_text = None
                        # 先试 OCR
                        try:
                            captcha_text = _ocr_captcha(captcha_img)
                        except Exception:
                            pass

                        if not captcha_text and on_captcha:
                            # OCR 失败 → 截图问人
                            captcha_path = os.path.join(work_dir, f"captcha_{target.replace('://', '_').replace('/', '_')[:50]}.png")
                            os.makedirs(os.path.dirname(captcha_path), exist_ok=True)
                            await page.screenshot(path=captcha_path)
                            captcha_text = await on_captcha(captcha_path)
                            if captcha_text:
                                captcha_text = captcha_text.strip()

                        if captcha_text:
                            # 重新填写登录表单（带上验证码）
                            login_ok = await _try_form_login(page, username, password, captcha=captcha_text)

                # 登录后等待跳转
                if login_ok:
                    await asyncio.sleep(3)
                    try:
                        await page.wait_for_url(
                            lambda u: not _detect_login_page(u),
                            timeout=10000,
                        )
                    except Exception:
                        pass

                    cookies = await context.cookies()
                    if cookies:
                        artifacts = await _extract_auth_artifacts(page, context)
                        result["success"] = True
                        result["method"] = "form_login"
                        result["cookies"] = artifacts.get("cookies") or _format_cookies(cookies)
                        result["token"] = artifacts.get("token") or ""
                        result["user_id"] = artifacts.get("user_id") or ""
                        result["reason"] = "表单自动登录成功"
                        await browser.close()
                        return result

            # ---- 第 3 步：登录失败，问人要 Cookie ----
            if on_need_cookie:
                cookie_str = await on_need_cookie(
                    f"自动登录失败（目标: {target}）。\n原因: {result.get('reason', '无有效凭证或登录表单识别失败')}"
                )
                if cookie_str:
                    result["success"] = True
                    result["method"] = "cookie_provided"
                    result["cookies"] = cookie_str
                    result["reason"] = "用户手动提供 Cookie"
                    await browser.close()
                    return result

            result["reason"] = "登录失败且无可用 Cookie"

        finally:
            await browser.close()

    return result


# ============================================================
# 页面分析辅助函数
# ============================================================

def _detect_login_page(url: str) -> bool:
    """检查 URL 是否像登录页"""
    login_patterns = [
        "/login", "/signin", "/auth", "/oauth",
        "/sso", "/account/login", "/user/login",
        "login.html", "signin.html",
        "/c4c3/account/login",  # 迪卡侬模式
    ]
    url_lower = url.lower()
    return any(p in url_lower for p in login_patterns)


async def _find_login_link(page) -> str | None:
    """在当前页面找登录链接"""
    try:
        links = await page.evaluate("""() => {
            const links = document.querySelectorAll('a[href]');
            const loginLink = Array.from(links).find(a => {
                const text = (a.textContent || '').toLowerCase();
                const href = (a.getAttribute('href') || '').toLowerCase();
                return text.includes('登录') || text.includes('login')
                    || text.includes('sign in') || text.includes('登入')
                    || href.includes('login') || href.includes('signin')
                    || href.includes('auth');
            });
            return loginLink ? loginLink.href : null;
        }""")
        return links
    except Exception:
        return None


async def _detect_login_form(page) -> bool:
    """检查页面是否有登录表单"""
    try:
        has_form = await page.evaluate("""() => {
            const forms = document.querySelectorAll('form');
            for (const form of forms) {
                const inputs = form.querySelectorAll('input');
                const types = Array.from(inputs).map(i => i.type || i.getAttribute('type') || 'text');
                const hasPassword = types.includes('password');
                const hasText = types.filter(t => t === 'text' || t === 'email' || t === 'tel' || !t).length > 0;
                if (hasPassword && hasText) return true;
            }
            // 也检查独立的密码输入框
            const pwdFields = document.querySelectorAll('input[type="password"]');
            return pwdFields.length > 0;
        }""")
        return has_form
    except Exception:
        return False


async def _try_form_login(
    page,
    username: str,
    password: str,
    captcha: str | None = None,
) -> bool:
    """尝试填写表单并提交登录"""
    try:
        # 找用户名输入框
        username_selectors = [
            'input[name="username"]',
            'input[name="user"]',
            'input[name="account"]',
            'input[name="loginName"]',
            'input[name="userName"]',
            'input[name="email"]',
            'input[name="phone"]',
            'input[name="mobile"]',
            'input[type="text"]',
            'input[type="email"]',
            'input[type="tel"]',
            'input[placeholder*="用户名"]',
            'input[placeholder*="账号"]',
            'input[placeholder*="手机"]',
            'input[placeholder*="邮箱"]',
            'input[placeholder*="Username"]',
            'input[placeholder*="Email"]',
        ]

        username_filled = False
        for sel in username_selectors:
            try:
                await page.fill(sel, username, timeout=3000)
                username_filled = True
                break
            except Exception:
                continue

        if not username_filled:
            return False

        # 找密码输入框
        password_selectors = [
            'input[name="password"]',
            'input[name="pwd"]',
            'input[name="pass"]',
            'input[type="password"]',
            'input[placeholder*="密码"]',
            'input[placeholder*="Password"]',
        ]

        password_filled = False
        for sel in password_selectors:
            try:
                await page.fill(sel, password, timeout=3000)
                password_filled = True
                break
            except Exception:
                continue

        if not password_filled:
            return False

        # 验证码
        if captcha:
            captcha_selectors = [
                'input[name="code"]',
                'input[name="captcha"]',
                'input[name="verifyCode"]',
                'input[name="captchaCode"]',
                'input[name="validCode"]',
                'input[placeholder*="验证码"]',
                'input[placeholder*="Captcha"]',
            ]
            for sel in captcha_selectors:
                try:
                    await page.fill(sel, captcha, timeout=3000)
                    break
                except Exception:
                    continue

        # 提交
        submit_selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("登录")',
            'button:has-text("登入")',
            'button:has-text("Login")',
            'button:has-text("Sign in")',
            'button:has-text("确定")',
            '[role="button"]:has-text("登录")',
        ]

        submitted = False
        for sel in submit_selectors:
            try:
                await page.click(sel, timeout=3000)
                submitted = True
                break
            except Exception:
                continue

        if submitted:
            await asyncio.sleep(3)
            return True

        # 如果按钮都没点到，尝试按回车
        try:
            await page.keyboard.press("Enter")
            await asyncio.sleep(3)
            return True
        except Exception:
            pass

        return False

    except Exception:
        return False


async def _find_captcha(page) -> bytes | None:
    """找验证码图片并返回其二进制内容"""
    try:
        # 找常见的验证码图片
        img_selectors = [
            'img[id*="captcha"]',
            'img[id*="code"]',
            'img[class*="captcha"]',
            'img[class*="code"]',
            'img[src*="captcha"]',
            'img[src*="code"]',
            'img[src*="verify"]',
        ]
        for sel in img_selectors:
            try:
                element = page.locator(sel).first
                if await element.count() > 0:
                    return await element.screenshot()
            except Exception:
                continue

        return None
    except Exception:
        return None


def _ocr_captcha(image_bytes: bytes) -> str | None:
    """OCR 识别验证码"""
    try:
        import io
        from PIL import Image
        import pytesseract

        img = Image.open(io.BytesIO(image_bytes))
        # 转灰度 + 二值化
        img = img.convert("L")
        img = img.point(lambda x: 0 if x < 128 else 255, "1")

        text = pytesseract.image_to_string(
            img,
            config="--psm 7 -c tessedit_char_whitelist=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        )
        text = text.strip().replace(" ", "")
        if len(text) >= 3:  # 验证码一般至少 3 个字符
            return text
        return None
    except ImportError:
        return None



# ============================================================
# 登录口发现 / 自动注册（无人值守）
# ============================================================

_LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth/login", "/user/login",
    "/account/login", "/accounts/login", "/member/login", "/admin/login",
    "/passport/login", "/sso/login", "/oauth/login", "/api/login",
    "/#/login", "/#/signin", "/web/login", "/portal/login",
]

_REGISTER_PATHS = [
    "/register", "/signup", "/sign-up", "/auth/register", "/user/register",
    "/account/register", "/accounts/register", "/member/register",
    "/passport/register", "/#/register", "/#/signup", "/web/register",
]


async def discover_auth_entry(page, target: str, kind: str = "login") -> str | None:
    """尽量找到登录/注册入口 URL。返回可 goto 的 URL 或 None。"""
    from urllib.parse import urljoin

    origin = target if "://" in target else f"https://{target}"
    # 1) 当前页链接
    try:
        href = await page.evaluate(
            """(kind) => {
              const keywords = kind === 'register'
                ? ['注册','register','signup','sign up','创建账号','立即注册']
                : ['登录','login','signin','sign in','登入','账号登录'];
              const links = Array.from(document.querySelectorAll('a[href],button,[role="button"]'));
              for (const el of links) {
                const text = ((el.textContent || '') + ' ' + (el.getAttribute('href') || '') + ' ' + (el.getAttribute('aria-label') || '')).toLowerCase();
                if (keywords.some(k => text.includes(String(k).toLowerCase()))) {
                  if (el.href) return el.href;
                  const h = el.getAttribute('href');
                  if (h) return h;
                }
              }
              return null;
            }""",
            kind,
        )
        if href:
            return urljoin(page.url, href)
    except Exception:
        pass

    # 2) 常见路径爆破（轻量 HEAD/GET via page.goto 太重，改用 request）
    paths = _REGISTER_PATHS if kind == "register" else _LOGIN_PATHS
    for path in paths:
        cand = urljoin(origin.rstrip("/") + "/", path.lstrip("/"))
        try:
            resp = await page.context.request.get(cand, timeout=8000)
            if resp.status < 400 or resp.status in (401, 403):
                # 401/403 也可能是登录接口
                return cand
        except Exception:
            continue
    return None


async def _extract_auth_artifacts(page, context) -> dict:
    """登录/注册后从 cookie、localStorage、页面内容提取 token/user_id。"""
    cookies = await context.cookies()
    cookie_str = _format_cookies(cookies)
    token = ""
    user_id = ""
    try:
        storage = await page.evaluate("""() => {
          const out = {};
          try {
            for (let i=0;i<localStorage.length;i++){
              const k = localStorage.key(i);
              out['ls:'+k] = localStorage.getItem(k);
            }
          } catch(e) {}
          try {
            for (let i=0;i<sessionStorage.length;i++){
              const k = sessionStorage.key(i);
              out['ss:'+k] = sessionStorage.getItem(k);
            }
          } catch(e) {}
          out['cookie'] = document.cookie || '';
          out['html'] = (document.body && document.body.innerText || '').slice(0, 3000);
          return out;
        }""")
    except Exception:
        storage = {}

    blob = " ".join(str(v) for v in (storage or {}).values())
    # token
    m = re.search(r"(?i)(?:access_token|accessToken|auth_token|token)[\"\'=\s:]+([A-Za-z0-9._\-]{10,})", blob)
    if m:
        token = m.group(1)
    # user id
    m = re.search(r"(?i)(?:userId|user_id|uid|memberId|member_id|accountId)[\"\'=\s:]+([A-Za-z0-9_\-]{1,64})", blob)
    if m:
        user_id = m.group(1)
    if not user_id:
        m = re.search(r'(?i)(?:userId|user_id|uid)=([A-Za-z0-9_\-]+)', cookie_str)
        if m:
            user_id = m.group(1)

    return {
        "cookies": cookie_str,
        "token": token,
        "user_id": user_id,
        "storage_keys": list((storage or {}).keys())[:30],
    }


async def try_register_and_login(
    target: str,
    work_dir: str,
    preferred_username: str | None = None,
    preferred_password: str | None = None,
) -> dict:
    """尽力自动注册并登录第二账号。失败不抛异常。"""
    import time
    import random
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"success": False, "reason": "Playwright 未安装"}

    # 生成可重复但不易冲突的测试账号
    stamp = str(int(time.time()))[-6:]
    rand = str(random.randint(100, 999))
    username = preferred_username or f"xinru_b_{stamp}{rand}"
    password = preferred_password or f"Xinru@{stamp}a1"
    email = f"{username}@example.com"
    phone = f"13{random.randint(100000000, 999999999)}"

    result = {
        "success": False,
        "username": username,
        "password": password,
        "cookies": None,
        "token": "",
        "user_id": "",
        "reason": "",
        "method": "register",
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        )
        page = await context.new_page()
        try:
            try:
                await page.goto(target, wait_until="load", timeout=20000)
            except Exception as e:
                result["reason"] = f"打开目标失败: {e}"
                await browser.close()
                return result
            await asyncio.sleep(1)

            reg_url = await discover_auth_entry(page, target, kind="register")
            if not reg_url:
                result["reason"] = "未发现注册入口"
                await browser.close()
                return result

            try:
                await page.goto(reg_url, wait_until="load", timeout=20000)
            except Exception:
                pass
            await asyncio.sleep(1)

            # 填注册表单（尽量多字段）
            field_map = [
                (['input[name="username"]','input[name="user"]','input[name="account"]','input[name="loginName"]','input[placeholder*="用户名"]','input[placeholder*="账号"]'], username),
                (['input[name="email"]','input[type="email"]','input[placeholder*="邮箱"]'], email),
                (['input[name="phone"]','input[name="mobile"]','input[type="tel"]','input[placeholder*="手机"]'], phone),
                (['input[name="password"]','input[type="password"]','input[placeholder*="密码"]'], password),
            ]
            filled_pwd = False
            for selectors, value in field_map:
                for sel in selectors:
                    try:
                        loc = page.locator(sel).first
                        if await loc.count() > 0:
                            await loc.fill(value, timeout=2500)
                            if "password" in sel or "密码" in sel:
                                filled_pwd = True
                            break
                    except Exception:
                        continue

            # 确认密码
            for sel in ['input[name="confirmPassword"]','input[name="password2"]','input[placeholder*="确认密码"]','input[placeholder*="重复密码"]']:
                try:
                    loc = page.locator(sel).first
                    if await loc.count() > 0:
                        await loc.fill(password, timeout=2000)
                        break
                except Exception:
                    continue

            # OCR 验证码（可选）
            captcha_img = await _find_captcha(page)
            if captcha_img:
                code = None
                try:
                    code = _ocr_captcha(captcha_img)
                except Exception:
                    code = None
                if code:
                    for sel in ['input[name="code"]','input[name="captcha"]','input[name="verifyCode"]','input[placeholder*="验证码"]']:
                        try:
                            await page.fill(sel, code, timeout=2000)
                            break
                        except Exception:
                            continue

            # 勾选协议
            try:
                for sel in ['input[type="checkbox"]']:
                    boxes = page.locator(sel)
                    count = await boxes.count()
                    for i in range(min(count, 3)):
                        try:
                            await boxes.nth(i).check(timeout=1000)
                        except Exception:
                            pass
            except Exception:
                pass

            # 提交
            submitted = False
            for sel in [
                'button[type="submit"]','input[type="submit"]',
                'button:has-text("注册")','button:has-text("Sign up")','button:has-text("Register")',
                'button:has-text("创建")','button:has-text("提交")',
            ]:
                try:
                    await page.click(sel, timeout=2500)
                    submitted = True
                    break
                except Exception:
                    continue
            if not submitted:
                try:
                    await page.keyboard.press("Enter")
                    submitted = True
                except Exception:
                    pass

            await asyncio.sleep(3)
            artifacts = await _extract_auth_artifacts(page, context)
            if artifacts.get("cookies") and (not _detect_login_page(page.url) or artifacts.get("token")):
                result.update({
                    "success": True,
                    "cookies": artifacts.get("cookies"),
                    "token": artifacts.get("token") or "",
                    "user_id": artifacts.get("user_id") or "",
                    "reason": f"自动注册成功并获得会话 (entry={reg_url})",
                })
                await browser.close()
                return result

            # 注册后可能要再登录
            login_url = await discover_auth_entry(page, target, kind="login")
            if login_url:
                try:
                    await page.goto(login_url, wait_until="load", timeout=15000)
                except Exception:
                    pass
                await asyncio.sleep(1)
                ok = await _try_form_login(page, username, password)
                if ok:
                    await asyncio.sleep(2)
                    artifacts = await _extract_auth_artifacts(page, context)
                    if artifacts.get("cookies"):
                        result.update({
                            "success": True,
                            "cookies": artifacts.get("cookies"),
                            "token": artifacts.get("token") or "",
                            "user_id": artifacts.get("user_id") or "",
                            "reason": f"注册后登录成功 (register={reg_url})",
                        })
                        await browser.close()
                        return result

            result["reason"] = f"注册流程已尝试但未拿到有效会话 (entry={reg_url}, filled_pwd={filled_pwd})"
        finally:
            await browser.close()
    return result


def _format_cookies(cookies: list[dict]) -> str:
    """把 Playwright cookie 列表转换成 HTTP Cookie 头格式"""
    return "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name") and c.get("value"))
