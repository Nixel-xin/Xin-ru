# BBASRC 测试范围（华晨宝马）

> 来源：用户提供的 BBASRC 资产范围与漏洞等级标准 V1.1（2024-02-03）  
> 用途：xinru agent 启动前 scope 约束、线索过滤、报告评级参考  
> 更新：2026-07-16

---

## 1. 总原则

- 只测 **in-scope** 资产；发现 out-of-scope 域名/接口只记录，不深挖、不作为确认漏洞提交。
- 提交评级以 **业务影响** 为准，不是单纯技术点名称。
- 同一系统短时间批量同类高危（如大量同质 SQLi/越权）：注意厂商保护机制，避免无效刷洞。

---

## 2. 收取资产范围（In-Scope）

### 2.1 通配域名

| 范围 | 说明 |
|---|---|
| `*.bmw-brilliance.cn` | 华晨宝马主业务相关 |
| `*.bba-app.biz` | BBA 应用域 |
| `*.lingyue-digital.com` | 领悦数字相关 |
| `*.bmw.com.cn` | 宝马中国相关 |
| `*.bmwcn.cloud` | 宝马中国云资产 |

### 2.2 明确单域名/主机

| 资产 |
|---|
| `www.bmw-afc.com.cn` |
| `www.heraldleasing.com` |
| `www.bmw-leasing.com.cn` |
| `whispers.bmw.com.cn` |
| `myprofile.bmw.com.cn` |
| `v-api.countly.bmw.com.cn` |
| `api.countly.bmw.com.cn` |

### 2.3 匹配规则（给 agent 用）

命中任一即视为 in-scope：

1. host 精确等于上表单域名  
2. host 自身或其父域匹配：
   - `bmw-brilliance.cn`
   - `bba-app.biz`
   - `lingyue-digital.com`
   - `bmw.com.cn`
   - `bmwcn.cloud`
3. 含子域示例：
   - `a.b.bmw.com.cn` ✅
   - `secure.bmw.com.cn` ✅
   - `xxx.bmwcn.cloud` ✅
   - `foo.bmw-brilliance.cn` ✅

> 注：`*.bmw.com.cn` 已覆盖 `whispers/myprofile/countly` 等；单列主机视为重点资产，不代表其他 `bmw.com.cn` 子域不收。

---

## 3. 不收取 / 排除（Out-of-Scope / 降级）

### 3.1 明确不收

| 排除项 | 处理 |
|---|---|
| `https://motorrad-activity.ali.bmwcn.cloud` 相关漏洞 | **暂不接收**；发现后标记 `out_of_scope`，不验证深挖、不提交 |
| **Tupu360 接口**相关漏洞 | **目前不收**；命中 `tupu360` 相关 API/域名/SDK 直接排除 |

### 3.2 无影响 / 不收类型（等级标准中的“无影响漏洞”）

以下即使技术存在，通常也 **不收 / 视为无影响**：

- 无关安全的 bug（乱码、页面打不开、功能不可用）
- 无实际意义的扫描器报告（Web Server 低版本等）
- Self-XSS
- 无敏感信息的 JSON Hijacking
- 无敏感操作的 CSRF
- 无意义源码泄漏
- 内网 IP / 域名泄漏（单独出现且不可利用）
- 401 基础认证钓鱼
- 程序路径信任问题
- 无敏感信息的 logcat 泄漏
- **非华晨宝马业务漏洞**

---

## 4. 漏洞等级评级标准 V1.1

### 4.1 严重（Critical）

1. 直接获取系统权限（服务器权限、重要业务客户端权限，如 **MyBMW**）：RCE、远程溢出、防火墙漏洞、可导致远程内核代码执行的逻辑问题等。  
2. 支付系统相关：订单篡改、可对用户/公司造成大量损失。  
3. 可获取或更改 **大量车主关联敏感信息**（车架号、车牌号、车主手机号、姓名、车贷等，**至少两项且能关联**，如车牌↔车主）；含订单遍历/修改、SQL 注入、任意账号密码修改等。  
4. 直接影响车辆安全：远程解锁、越权控制他人车辆/充电桩。  
5. 可直接影响车辆生产：可能导致工厂停产，或修改工控车辆制造参数。

### 4.2 高危（High）

1. 重要业务系统的越权敏感操作：越权改重要信息、订单普通操作、重要业务配置修改等。  
2. 弱口令/认证绕过进入后台，且具备实际权限或敏感信息。  
3. 高风险信息泄露：可直接利用的敏感数据泄漏、可批量获取部分车主敏感信息、车辆生产数据泄漏。  
4. 敏感信息越权访问：绕过认证进管理后台、后台弱密码、可拿内网敏感信息的 **回显型 SSRF**。  
5. 普通 SQL 注入：能取数，但不含/仅少量敏感信息。

### 4.3 中危（Medium）

1. 普通信息泄漏：web/系统路径遍历等。  
2. 无需交互即可危害用户：存储型 XSS、缺少 CSRF Token 的敏感操作等。  
3. 普通越权：查看/修改/删除非核心系统订单、记录等。  
4. 普通逻辑/流程缺陷。  
5. 移动客户端敏感信息泄露（不含 Android 系统漏洞）：调试信息、逻辑漏洞、功能访问导致的用户名/密码/密钥/手机串号等泄露。

### 4.4 低危（Low）

1. 难利用但有隐患：可能传播利用的存储型 XSS（含存储型 DOM-XSS）、非重要敏感操作 CSRF。  
2. SSRF 到内网，无回显/部分回显，且未拿到敏感信息或服务权限。  
3. 移动客户端本地拒绝服务。

### 4.5 无影响（Informational / 不收）

见第 3.2 节。

---

## 5. 厂商保护机制（提交策略）

若同一系统短时间出现大量同类高危（如大批 SQLi/越权）：

1. 审核员可能判定系统几乎无防护，并与厂商确认是否继续收该类洞。  
2. 若厂商表示该类已知不收：
   - 平台通常只正常审核 **前 3 个** 同类型漏洞；
   - 其余同类型 **降级**；
   - 并通知该系统该类型暂停收取，直到厂商修复后重开。

**Agent/人工策略建议：**

- 同系统同类型高危 concisely 验证后，优先提交 **质量最高、影响最大** 的前 1–3 个；
- 其余合并为“同类面扩大说明”，避免无效刷量。

---

## 6. 给 xinru Agent 的执行约束

### 6.1 目标选择

- 主入口可从 in-scope 任选，例如：
  - `https://www.bmw.com.cn`
  - `https://myprofile.bmw.com.cn`
  - `https://whispers.bmw.com.cn`
- 子域名发现/线索补收：仅保留 in-scope host。
- 命中 `motorrad-activity.ali.bmwcn.cloud` 或 `tupu360`：标记排除，不进入验证链。

### 6.2 认证与双账号

- 涉及 MyBMW / myprofile / 车主信息 / 订单 / 车辆控制：优先配置 **A/B 双身份**（Cookie + 账号密码双给）。
- 无账号时仅做未授权/信息泄露面，不强行宣称越权确认。

### 6.3 验证与定级映射（简化）

| 技术现象 | 初判方向 |
|---|---|
| RCE / 重要客户端权限 | 严重 |
| 支付篡改、批量车主 PII 关联泄露 | 严重 |
| 远程控车/充电桩越权 | 严重 |
| 重要业务越权、后台弱口令有权限、回显 SSRF 拿敏感 | 高危 |
| 普通 SQLi 取非敏/少量敏 | 高危 |
| 存储 XSS、普通越权、普通逻辑洞 | 中危 |
| 难利用 XSS/CSRF、无敏感 SSRF | 低危 |
| Self-XSS、无敏 CSRF、纯版本扫描 | 无影响/不收 |

### 6.4 报告输出要求

每个确认项至少包含：

- 资产 host（证明 in-scope）
- 影响业务与数据（是否车主/支付/车辆/生产）
- 利用条件（是否需登录、是否双账号、是否可批量）
- 证据（请求/响应）
- 建议等级（严重/高危/中危/低危）与对应条款编号

---

## 7. 快速资产清单（Seed Targets）

可直接作为 agent 初始 targets 的种子（按需裁剪）：

```text
https://www.bmw.com.cn
https://myprofile.bmw.com.cn
https://whispers.bmw.com.cn
https://v-api.countly.bmw.com.cn
https://api.countly.bmw.com.cn
https://www.bmw-afc.com.cn
https://www.heraldleasing.com
https://www.bmw-leasing.com.cn
```

通配域需通过子域名收集扩展，但过滤规则必须走 in-scope matcher。

---

## 8. 变更记录

| 日期 | 内容 |
|---|---|
| 2026-07-16 | 初版：整理 BBASRC 收取范围、排除项、等级 V1.1、厂商保护机制与 agent 约束 |
