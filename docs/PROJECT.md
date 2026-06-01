# ACME SSL 证书管理门户 — 完整项目手册

> **阅读本文档后，你将获得和主开发者（AI 小X）同等的项目认知。**
> 这包含了从零搭建到所有 Bug 修复的完整历程。

---

## 一、项目起源与目标

用户谢海涛需要一套 SSL 证书管理系统，能通过 Web 界面签发 Let's Encrypt 免费证书，支持多用户、额度控制、批量操作。

**核心需求**：
- 用户注册/登录（邮箱+验证码+密码）
- 为域名签发 SSL 证书（Let's Encrypt DNS-01 验证）
- 支持泛域名 `*.example.com`
- 多用户额度管理
- 管理员面板
- 好看的二次元风格界面

## 二、技术栈与架构

```
用户浏览器
    │
    ▼ HTTPS
Nginx (yumingzhengshu.byfwwwg.cn)
    │ /acme/ → proxy_pass http://127.0.0.1:10501/
    │ 注意：Nginx 会 strip /acme/ 前缀，Flask 收到的是 /
    ▼
Flask acme_portal.py (端口 10501)
    │
    ├── SQLite (state/portal.db)  — WAL 模式
    ├── ACME v2 → Let's Encrypt   — 通过 acme 库 + josepy
    └── SMTP (QQ邮箱) → 验证码发送
```

**前端**：纯 HTML/CSS/JS 单文件 SPA，零框架
**后端**：Flask 2.0.3 + Python 3.6.8
**ACME**：acme 3.0.1 + josepy 1.15.0 + cryptography 47.0.0

## 三、服务器信息

| 项目 | 值 |
|------|-----|
| IP | 39.96.222.85 |
| 厂商 | 阿里云，华北2-北京 |
| 系统 | Alibaba Cloud Linux 3 (≈CentOS 8) |
| Python | 3.6.8 |
| SSH 用户 | root |
| SSH 密码 | 123xht.. |
| SSH 方式 | pty + select 交互式（无 sshpass/expect） |

## 四、文件结构

### 本地（开发机）
```
/home/xht/.openclaw/workspace/acme_dns01/
├── acme_portal.py          # 后端 Flask 应用（约 42000 字节）
├── templates/
│   └── portal.html         # 前端 SPA（约 65000 字节）
├── PROJECT.md              # ← 你正在读的这份文档
└── deploy.sh               # 远程部署脚本
```

### 远程（生产服务器）
```
/opt/acme-dns01/
├── acme_portal.py
├── templates/
│   └── portal.html
├── state/
│   ├── portal.db           # SQLite 数据库
│   ├── account_key.pem     # LE 账号 RSA 4096 密钥
│   └── <domain>/           # 每个域名一个子目录
│       ├── state.json      # ACME 订单完整状态
│       ├── fullchain.pem   # 证书链
│       └── domain_key.pem  # 域名私钥 RSA 2048
└── deploy.sh
```

### 服务配置
```ini
# /etc/systemd/system/acme-portal.service
[Service]
ExecStart=/usr/bin/python3 /opt/acme-dns01/acme_portal.py 10501
Environment="SMTP_HOST=smtp.qq.com"
Environment="SMTP_PORT=465"
Environment="SMTP_USER=xiexianshen@foxmail.com"
Environment="SMTP_PASS=zpkvtpsovhbqdhdh"
Environment="SMTP_FROM=xiexianshen@foxmail.com"
```

## 五、部署流程（重要！）

这是唯一正确的部署方式。不走这套流程会出问题。

```bash
# 1. 本地编码
cd /home/xht/.openclaw/workspace/acme_dns01
base64 -w0 acme_portal.py > /tmp/p64_acme
base64 -w0 templates/portal.html > /tmp/p64_portal

# 2. 通过 SSH 分块上传（每块 3800 字符）
#    使用 Python pty + select 交互式传密码
#    上传脚本在项目里有现成的

# 3. 远程解码
base64 -d /tmp/p64_up > /opt/acme-dns01/<target_file>
rm -f /tmp/p64_up

# 4. 重启服务
systemctl restart acme-portal

# 5. 用户端强制刷新（不清缓存会有旧 JS）
#    告诉用户：Ctrl+F5
```

**注意事项**：
- 本地和远程文件大小可能差 1 字节（换行符），以内容为准
- 一次只上传一个文件，先传 .py 重启，再传 .html 重启
- 两个文件都改了就上传两次，每次都会重启服务

## 六、Python 3.6 兼容性禁区

**服务器 Python 是 3.6.8，以下语法会导致 500 错误**：

| 禁止 | 替代 |
|------|------|
| `dict[str, Any]` | 不加类型注解 |
| `dict \| None` | 不加类型注解 |
| `f"{x=}"` (3.8+) | `f"x={x}"` |
| `cert.not_valid_after_utc` | `cert.not_valid_after` |
| `list[str]` | `list` 或注释 |

**SQLite datetime**：格式 `2026-05-15 09:00:00`（空格分隔，非 ISO T 分隔）

## 七、代码关键函数速查

### `_make_engine(domain)` → (ak, jwk, net, cli)
创建 ACME 客户端。加载/创建账号密钥，连接 Let's Encrypt Directory，注册账号。
**注意**：`net.post()` 必须传 `acme_version=2`

### `_ensure_cert_record(db, uid, domain, state)`
将证书记录写入数据库。从 `state["certificate"]` 解析到期时间。
**注意**：必须在 `app.app_context()` 内调用，且 `uid` 不能从 `g` 取。

### `api_acme_generate()`
批量生成 DNS 验证记录。支持换行/逗号/分号分隔的域名。
**注意**：已存在的订单不覆盖（检查 `status=="completed"` 或 `fullchain.pem` 存在）

### `api_acme_verify()` → `_verify_bg()`
后台线程执行 ACME 验证全流程：答挑战 → 轮询验证 → 签发 → 下载证书 → 写入文件。
**注意**：`_ensure_cert_record` 用 `state["user_id"]` 不是 `g.user_id`

### `update_cert_statuses()`
定期更新证书过期状态（只改 `valid`/`expiring_soon` 的记录）

### 关键变量
- `_running: dict` — 正在执行的验证线程（domain → Thread）
- `STATE_ROOT = Path("/opt/acme-dns01/state")`
- `DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"`

## 八、前端关键函数速查

| 函数 | 作用 |
|------|------|
| `initAuth()` | 页面加载时检查 token，决定显示登录页还是应用 |
| `enterApp(user)` | 进入主应用，渲染侧边栏 |
| `refreshDashboard()` | 刷新证书面板（统计+列表） |
| `showDetail(cid)` | 打开证书详情弹窗 |
| `verifyCert(domain)` | 面板里点击「验证」按钮 |
| `acmeGenerate()` | 签发流程 step1→step2：生成 DNS 记录 |
| `acmeVerify()` → `acmeVerifyNext()` | 签发流程 step2→step3：验证域名 |
| `acmeShowCert(d)` | 签发流程 step3：展示证书 |
| `pollCertStatus(domain, item)` | 轮询验证状态（120次×3秒 = 6分钟超时） |
| `copyText(btn)` | 复制按钮逻辑，从 `data-value` 取原始值 |
| `downloadCert(cid, type)` | fetch + Blob 下载（不用 `<a>` 直接请求，否则没 token） |

### 关键变量
- `TOKEN` — JWT，存 localStorage
- `USER` — 当前用户对象
- `currentDomains` — 批量签发域名列表
- `verifyIndex` — 当前验证到第几个域名

## 九、完整 Bug 历史与教训

### Bug 1：证书详情弹窗点不动 / 弹窗跑到页面底部
**时间**：2026-05-15 14:01
**现象**：点击证书面板的「详情」按钮，弹窗出现在页面底部，需要滚动才能看到。
**根因**：之前为了修 z-index 分层，加了一条 CSS：
```css
.auth-page, .app, .modal-overlay { position: relative; z-index: 1; }
```
`.modal-overlay` 把弹窗的 `position: fixed` 覆盖成了 `relative`，弹窗跟着页面流跑了。
**修复**：从该规则中移除 `.modal-overlay`。
**教训**：**CSS 改动后必须测试弹窗**。任何全局样式改动都可能影响看似无关的组件。

### Bug 2：登录后刷新闪出登录界面
**时间**：2026-05-15 14:01
**现象**：已登录状态刷新页面，会短暂看到登录页再跳到应用。
**根因**：`#authPage` 默认 `display: flex` 可见，浏览器先渲染登录页，然后 JS 才读到 localStorage 里的 token 并切换到应用。中间那帧就闪了。
**修复**：`#authPage` 默认改为 `display: none`，鉴权逻辑从 `DOMContentLoaded` 事件改为立即执行脚本（在 body 末尾同步执行，浏览器还没绘制）。
**教训**：**页面初始状态要考虑已登录场景**。visible-by-default 的元素在 JS 执行前就会被渲染。

### Bug 3：偶尔闪屏
**时间**：2026-05-15 14:01-14:05
**现象**：界面偶尔出现闪烁/白屏。
**根因**：多个常驻 UI 元素（侧边栏、卡片、证书列表、按钮）使用了 `backdrop-filter: blur()`，配合 Canvas 60fps 雨滴动画 + 闪电效果，GPU 合成层频繁重建。
**修复**：
- 侧边栏/统计卡片/证书项/容器/按钮 → 改用纯色半透明背景，去除 backdrop-filter
- 仅弹窗和登录卡保留 backdrop-filter（不常驻）
- 闪电效果完全移除（用户要求）
- Canvas 加 `will-change: transform` 提升到独立 GPU 层
**教训**：**backdrop-filter 是昂贵的 CSS 属性**。不要在大面积常驻元素上使用。配合持续动画会加剧 GPU 压力。

### Bug 4：签发证书报 "JWS header parameter 'url' required"
**时间**：2026-05-15 14:05-14:16
**现象**：新域名签发时报 ACME 错误。
**根因（双重）**：
1. `_verify_bg` 中用 `net.get(url)` 获取授权/挑战/订单状态。`ClientNetwork.get()` 是纯 HTTP GET，不经过 JWS 签名。但 Let's Encrypt 的 Boulder 服务器要求 ACME v2 所有资源请求都用 POST-as-GET（POST 空 body + JWS 签名）。
2. `_make_engine` 中 `net.post(d.newAccount, ...)` 没传 `acme_version` 参数，默认 version=1。在 v1 模式下 `_wrap_in_jws` 不添加 `url` 到 JWS header。
**修复**：
1. 所有 `net.get(resource_url)` 改为 `cli._post_as_get(resource_url)`（共 5 处）
2. `net.post(d.newAccount, ...)` 显式加 `acme_version=2`
**教训**：
- **acme 库的 ClientNetwork 不懂 ACME v2**。它的 `get()` 是纯 GET，`post()` 默认 v1。
- **ClientV2 才是 v2 正确的入口**。所有 ACME 资源访问应通过 `cli._post()` / `cli._post_as_get()`。

### Bug 5：证书签发后始终显示"验证中/处理中"
**时间**：2026-05-15 14:25-14:29
**现象**：证书验证成功、fullchain.pem 已写入磁盘，但证书面板一直显示"处理中"，DB 状态也是 pending。
**根因（三重）**：
1. 后台线程 `_verify_bg` 调用 `_ensure_cert_record(db, g.user_id, domain, state)`，但线程用了 `app.app_context()` 后 `g` 是全新空对象，`g.user_id` 抛出 `AttributeError`
2. `_ensure_cert_record` 内部的 `db.execute()` 被 `try: except: pass` 静默吞掉
3. 证书文件写成功了（`fullchain.pem` 存在），但 DB 里永远是 pending
**修复**：
- 第一步：`_ensure_cert_record` 调用处加 `with app.app_context():`
- 第二步（关键）：`g.user_id` 改为 `state["user_id"]`（state dict 里存了 user_id）
**教训**：
- **Flask `g` 是请求级别的**。子线程即便推了 `app_context`，`g` 也是空的。
- **闭包传数据**：后台线程需要的数据在创建线程前存进 dict/闭包，不要依赖 `g`。
- **别用 `except: pass`**。至少打日志。这个 Bug 被静默吞了 3 次。

### Bug 6：刷新页面后丢失签发流程
**时间**：2026-05-15 14:34-14:36
**现象**：用户在签发流程 step 2（DNS 记录展示页）刷新页面，DNS 信息丢失，不知道该怎么继续。
**修复**：证书面板中 pending/verifying 状态的证书增加「🔍 验证」按钮。点击后：
1. 弹出自定义 modal 展示 DNS TXT 记录（主机记录+记录值，带复制按钮）
2. 确认后启动验证
3. 轮询状态，完成后自动刷新面板
**教训**：**关键流程不能只靠线性步骤**。任何步骤都可能被刷新打断，需要从列表页也能重入。

### Bug 7：api/acme/generate 覆盖已完成订单
**时间**：2026-05-15 15:10-15:13
**现象**：已签发的证书状态又变成"处理中"。
**根因**：`verifyCert()` 先调用 `api/acme/generate` 获取 DNS 记录，但 generate 端点对已完成的域名（status="completed"）没有特殊处理，直接创建了新 ACME 订单，覆盖了已签发的 state.json。
**修复**：
- 后端：generate 端点加检查 `status=="completed" or fullchain.pem exists` → 直接返回已有信息
- 前端：verifyCert 收到 completed 时提示「已签发」并刷新面板
- api/verify 端点：加兜底检查 `fullchain.pem` 存在就返回 completed（不看 status 字段）
**教训**：**生成端点必须有幂等性**。已完成的资源绝不能重新创建。

### Bug 8：DNS TXT 弹窗复制按钮粘连文字
**时间**：2026-05-15 14:39-14:42
**现象**：点复制按钮，复制出来的值末尾带着 `📋`。
**根因**：`copyText()` 用 `parentElement.textContent` 取值，包含了按钮内的 emoji 文字。
**修复**：用 `data-value` 属性存储原始值，复制时读属性而非 textContent。
**教训**：**复制功能不要依赖 DOM 文字拼接**。用专属属性存储原始值。

### Bug 9：弹窗用 confirm() 不能复制
**时间**：2026-05-15 14:50-14:52
**现象**：浏览器 `confirm()` 弹窗不能选中复制文字。
**修复**：自定义 modal + copy 按钮。
**教训**：**浏览器原生弹窗能不用就不用**。自定义弹窗体验更好。

## 十、设计决策记录

| 决策 | 原因 |
|------|------|
| 额度用 `total_issued` 而非 `COUNT(certificates)` | 防止删除证书恢复额度 |
| 下载用 fetch+Blob | `<a>` 标签直接下载不带 Authorization header |
| 管理员不能删除管理员 | `WHERE is_admin=0` |
| 密码不可查看原文 | SHA256 哈希，用"重置密码"替代 |
| 登录页默认密码模式 | 用户偏好 |
| SQLite WAL 模式 | 支持并发读写（后台线程+请求线程） |
| 证书到期前 7 天标红 | 提前预警 |
| 验证码不区分大小写 | 用户体验 |
| JWT 7 天有效 | 平衡安全与便利 |

## 十一、数据库

```sql
-- 用户表
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    is_admin INTEGER DEFAULT 0,
    max_certs INTEGER DEFAULT 5,      -- 额度上限，-1 = 无限
    total_issued INTEGER DEFAULT 0,   -- 累计签发数（永增不减）
    created_at TEXT,
    last_login TEXT
);

-- 证书表
CREATE TABLE certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    status TEXT DEFAULT 'pending',    -- pending/valid/expiring_soon/expired/invalid/error
    issued_at TEXT,
    expires_at TEXT,
    created_at TEXT,
    UNIQUE(user_id, domain)
);

-- 验证码表
CREATE TABLE verify_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    code TEXT NOT NULL,
    created_at TEXT,
    used INTEGER DEFAULT 0
);
```

## 十二、管理员功能

- **管理员**：3065093357@qq.com / 123xht..
- 查看全部用户证书
- 创建用户（邮箱+密码+额度）
- 设置用户证书额度（-1=无限）
- 重置用户密码（返回明文）
- 删除用户（同步清除证书）
- **切换身份**：生成目标用户的 JWT 直接模拟登录

## 十三、接口完整列表

### 认证
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /api/auth/send_code | 发送验证码 |
| POST | /api/auth/login | 登录（密码/验证码） |
| GET | /api/auth/me | 当前用户信息 |
| POST | /api/auth/set_password | 设置密码 |

### 证书
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/certs | 证书列表+统计 |
| GET | /api/certs/\<id\> | 证书详情 |
| DELETE | /api/certs/\<id\> | 删除证书 |
| GET | /api/certs/\<id\>/download/\<type\> | 下载 cert/key/all |

### ACME
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /api/acme/generate | 生成 DNS 记录（批量） |
| POST | /api/acme/verify | 开始验证（后台线程） |
| POST | /api/acme/status | 查询验证状态 |
| GET | /api/acme/download/\<domain\>/\<type\> | 下载签发结果 |
| POST | /api/acme/email | 发证书到邮箱 |

### 管理员
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/admin/users | 用户列表 |
| POST | /api/admin/create_user | 创建用户 |
| PUT | /api/admin/users/\<id\>/quota | 设置额度 |
| PUT | /api/admin/users/\<id\>/reset_password | 重置密码 |
| DELETE | /api/admin/users/\<id\> | 删除用户 |
| POST | /api/admin/users/\<id\>/login_as | 模拟登录 |

## 十四、运维速查

```bash
systemctl restart acme-portal     # 重启（改代码后必做）
systemctl status acme-portal      # 状态
journalctl -u acme-portal -n 30   # 日志
ss -tlnp | grep 10501             # 端口检查
sqlite3 /opt/acme-dns01/state/portal.db "SELECT * FROM users;"
```

## 十五、改代码后必测清单

```
□ 登录（密码模式 + 验证码模式）
□ 证书面板 — 统计数字正确、列表显示正常
□ 详情弹窗 — 点击后居中弹出、可关闭
□ 签发 — 输入域名 → 生成 DNS 记录 → 复制按钮正常
□ 验证 — 弹窗显示正确的 TXT 记录 → 验证按钮可用
□ 下载 — 证书/私钥/打包下载均可
□ 管理员 — 用户列表、创建、额度、删除、切换
□ 刷新 — 已登录状态刷新不闪登录页
□ 弹窗 — 点击遮罩层可关闭
```

## 十六、与新 AI 协作指南

**如果你是第一次接手这个项目的 AI，请按以下步骤操作：**

1. 读完本文档（你已经完成了 ✅）
2. 阅读 `acme_portal.py` 了解后端
3. 阅读 `templates/portal.html` 了解前端
4. **做任何修改前**，确认：代码用 Python 3.6 语法了吗？在后台线程用 `g` 了吗？
5. **修改完成后**，走一遍第十五节的测试清单
6. **部署后**，提醒用户 Ctrl+F5 强制刷新

**最重要的一条**：这个项目的代码在反复修改中积累了一些历史包袱。如果某个功能看起来「明明应该这样写但实际是那样写的」，很可能是有意为之（为了兼容 Python 3.6 或绕过 ACME 库的坑）。**先读注释和上下文，再改。**
