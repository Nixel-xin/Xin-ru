# BBASRC 目标分组：哪些需要你先登录

> 目的：按目标拆分，你只登录“需要身份”的站，稍后把 Cookie/Token（最好再加账号密码）给我。  
> 说明：当前网络探测不稳定时，先按业务性质分组；你回传后我再按实际会话验证。

---

## A. 需要身份（请你先登录）

这些目标最可能涉及车主/个人中心/业务后台，**越权、订单、个人信息**都靠身份：

| 优先级 | 目标 | 为什么需要身份 | 你登录后请给我 |
|---|---|---|---|
| P0 | `https://myprofile.bmw.com.cn` | 个人资料/车主身份面，越权和敏感信息高价值 | A/B 两套：Cookie + 账号密码（Token 有就给） |
| P0 | `https://secure.bmw.com.cn` | 常见安全/登录相关入口，认证后业务接口多 | A/B Cookie（或登录后全站 Cookie） |
| P0 | MyBMW 相关登录态（若你平时从官网/App 进） | 等级标准里明确点名 MyBMW 客户端权限 | A/B 会话；若是 App，抓包 Token/Cookie |
| P1 | `https://whispers.bmw.com.cn` | 名称与业务形态通常偏登录后内容/互动 | 能进业务页的 Cookie/Token |
| P1 | `https://www.bmw-afc.com.cn` | 金融/车贷相关，常需客户登录 | A/B 客户账号会话 |
| P1 | `https://www.bmw-leasing.com.cn` | 租赁业务，订单/合同/客户信息常需登录 | A/B 客户账号会话 |
| P1 | `https://www.heraldleasing.com` | 租赁相关，逻辑同金融业务 | A/B 客户账号会话 |

### 你怎么给我（推荐格式）

每个需要身份的目标，尽量 **A/B 双身份**，并且 **Cookie + 账号密码双给**：

```text
### myprofile.bmw.com.cn
A_user: 账号A
A_pass: 密码A
A_cookie: k1=v1; k2=v2; ...
A_token: Bearer xxxx   # 没有可写无
A_notes: 登录后打开了哪些页面

B_user: 账号B
B_pass: 密码B
B_cookie: k1=v1; k2=v2; ...
B_token: Bearer yyyy
B_notes: 与A同权限/不同用户
```

同格式复制给：

- `secure.bmw.com.cn`
- `whispers.bmw.com.cn`（如有账号）
- `www.bmw-afc.com.cn`
- `www.bmw-leasing.com.cn`
- `www.heraldleasing.com`

> 如果多个站其实是同一套 SSO（同一登录中心），也请按“登录后分别打开每个目标站”，把**每个站域名下的 Cookie** 分开导出。  
> 浏览器里只导出当前站 Cookie 时，最稳。

---

## B. 可先匿名测（你暂时不用登录）

这些可先做未授权、信息泄露、接口暴露、配置泄露，不挡主流程：

| 目标 | 先测什么 |
|---|---|
| `https://www.bmw.com.cn` | 前端源码、公开接口、表单入口、未授权访问 |
| `https://v-api.countly.bmw.com.cn` | 统计/采集 API 未授权、信息泄露 |
| `https://api.countly.bmw.com.cn` | 同上 |
| 其他 in-scope 子域（收集后自动扩展） | 先未授权；若撞登录墙再回头要身份 |

---

## C. 明确不做

- `https://motorrad-activity.ali.bmwcn.cloud`（暂不接收）
- 任何 **Tupu360** 接口相关

---

## D. 建议你现在只做这些登录

为了不浪费时间，**优先只登录这 3 个**：

1. `https://myprofile.bmw.com.cn`（A/B）
2. `https://secure.bmw.com.cn`（A/B，如可进）
3. 金融/租赁三选一你有账号的：
   - `https://www.bmw-afc.com.cn`
   - `https://www.bmw-leasing.com.cn`
   - `https://www.heraldleasing.com`

有余力再补：

4. `https://whispers.bmw.com.cn`

---

## E. 你回传后我会怎么跑

1. 先跑 **B 组匿名目标**（不等你）  
2. 你给到身份后，再跑 **A 组登录后目标**（双账号越权重点）  
3. 全程按 BBASRC scope 过滤，不碰排除项

---

## F. 最小可用回传（如果赶时间）

至少给我：

```text
1) myprofile.bmw.com.cn
- A cookie
- B cookie
- A/B 账号密码（可回落）

2) secure.bmw.com.cn（如果和 myprofile 不是同一套会话）
- A/B cookie
```

有这套，就能先把最高价值的身份相关面跑起来。
