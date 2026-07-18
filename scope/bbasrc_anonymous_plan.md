# BBASRC 匿名可测方案（无账号）

> 前提：需要身份的目标（myprofile/secure/whispers/金融租赁等）当前打不开或无入口，用户无法提供 A/B 会话。  
> 策略：只跑**当前可达 + 无需登录**资产，做未授权/信息泄露/前端源码审计。

## 可测目标

| 目标 | 原因 |
|---|---|
| `https://www.bmw.com.cn` | 可达，公开官网，可收集 JS/接口/表单 |
| `https://v-api.countly.bmw.com.cn` | 可达，统计 API |
| `https://api.countly.bmw.com.cn` | 可达，统计 API |

## 暂缓（无身份/不可达）

- `myprofile.bmw.com.cn`（根路径 404）
- `whispers.bmw.com.cn`（根路径 404）
- `secure.bmw.com.cn`（解析失败）
- `www.bmw-afc.com.cn` / `www.heraldleasing.com`（超时）
- `www.bmw-leasing.com.cn`（502）
- MyBMW 登录后业务（无账号）

## 测试重点（无账号也能做）

1. 前端 JS / sourcemap / 配置泄露（密钥、内部域名、API）
2. 未授权接口访问
3. 公开表单/预约试驾等参数篡改（谨慎、低侵）
4. Countly API 信息暴露 / 未授权
5. 子域名扩展后仍 in-scope 且匿名可达的资产
6. **不做**：越权（需双账号）、车主信息、支付登录后流程

## 排除

- `motorrad-activity.ali.bmwcn.cloud`
- Tupu360

## 评级预期

无登录态时，高概率产出集中在：
- 信息泄露 / 未授权接口 / 配置问题 → 中低危为主
- 若打到硬编码密钥、批量未授权敏感数据 → 仍可冲高危
- 严重级（控车/大量车主关联信息/支付大损失）在无账号条件下较难

## 启动命令

```bash
cd agent
./venv/bin/python run_bbasrc.py \
  --targets 'https://www.bmw.com.cn,https://v-api.countly.bmw.com.cn,https://api.countly.bmw.com.cn' \
  --no-path-brute
```

不传 credentials/cookies。
