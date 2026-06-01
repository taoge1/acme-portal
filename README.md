# ACME SSL 证书管理门户

> 🚀 基于 Let's Encrypt DNS-01 验证的免费 SSL 证书自动签发管理平台

一键签发、多用户管理、额度控制、美观界面。支持泛域名、批量签发、7 天到期提醒。

![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.0-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-lightgrey)

---

## 📦 快速开始（推荐）

### Windows 用户

**不需要安装 Python，不需要配置环境。** 下载 `ACME证书管理.exe`，双击运行：

1. **双击** `ACME证书管理.exe`
2. 弹出命令行窗口，自动启动服务
3. 浏览器打开 http://localhost:10501
4. 用管理账号登录：`admin@example.com` / `admin123`
5. 开始签发免费 SSL 证书！

> 💡 命令行窗口不要关，关了服务就停了。可以最小化到任务栏。

### Linux / macOS 用户

下载 `acme-portal` 可执行文件：

```bash
chmod +x acme-portal
./acme-portal
# 浏览器打开 http://localhost:10501
```

### 管理员账号

| 账号 | 说明 |
|------|------|
| `admin@example.com` | 管理员，可管理所有用户和证书 |
| `admin123` | 初始密码，登录后建议修改 |

> ⚠️ 首次启动会自动创建管理员账号。可以通过环境变量 `ADMIN_EMAIL` 和 `ADMIN_PASSWORD` 自定义。

---

## ✨ 功能一览

### 🎫 证书管理
- **Let's Encrypt DNS-01 验证** — 支持 `*.example.com` 泛域名证书
- **一键签发** — 输入域名，生成 DNS TXT 记录，配好记录后验证签发
- **批量签发** — 一次输入多个域名，各域名独立签发
- **下载** — 证书/私钥/打包下载
- **到期监控** — 到期前 7 天自动标红提醒

### 🔐 多用户系统
- **邮箱验证码登录 / 密码登录**
- **额度控制** — 每个用户可设置签发上限（-1 = 无限）
- **管理员面板** — 查看所有证书、管理用户、切换身份模拟登录

### 🎨 界面
- 毛玻璃效果 + 二次元风下雨动画（雨丝 + 雾气 + 水花）
- 暗色微紫主题，响应式设计

---

## 🚀 签发证书的完整流程

这个工具使用 **DNS-01 验证**，你需要手动在域名管理后台添加 TXT 记录。

### 第一步：登录

浏览器打开 http://localhost:10501，用管理员账号登录。

### 第二步：输入域名

在证书面板点击「签发证书」，输入你想要证书的域名，例如：

```
example.com
*.example.com
blog.example.com
```

> 每行一个域名，每个域名会独立签发一张证书（不是 SAN 合并）。

### 第三步：添加 DNS TXT 记录

系统会为每个域名生成一条 DNS TXT 记录。你需要：

1. 登录你的域名注册商（阿里云、DNSPod、Cloudflare、Godaddy 等）
2. 找到域名的 DNS 管理页面
3. 添加一条 TXT 记录：
   - **主机记录**：`_acme-challenge`（或 `_acme-challenge.example.com`）
   - **记录类型**：`TXT`
   - **记录值**：系统生成的一串字符（直接复制）
4. 保存后等待 DNS 生效（一般 1-5 分钟）

### 第四步：验证签发

回到工具页面，点击「验证」按钮。系统会：

1. 检查 DNS TXT 记录是否已配置
2. 通知 Let's Encrypt 验证
3. 验证通过后自动签发证书
4. 证书文件保存到服务器/本地

### 第五步：下载证书

签发完成后，点击「下载」即可获取：
- `fullchain.pem` — 证书链
- `domain_key.pem` — 私钥
- 打包下载（两个文件一起）

---

## 🏗 技术栈

| 层级 | 技术 |
|------|------|
| 后端 | Flask 2.0 + Python |
| 前端 | 纯 HTML/CSS/JS SPA（零框架） |
| 证书 | Let's Encrypt / ACME v2 |
| 数据库 | SQLite |
| 验证码 | SMTP（可选配置） |

---

## 📁 项目结构（开发者）

```
acme-portal/
├── acme_portal.py              # 主力后端 Flask 应用
├── templates/
│   └── portal.html             # 前端 SPA
├── state/                      # 运行时数据（证书、数据库）
├── deploy/
│   ├── acme-portal.service     # systemd 服务示例
│   └── deploy.sh               # 部署脚本
├── archive/                    # 旧版代码
├── docs/
│   └── PROJECT.md              # 完整项目文档
├── build_linux.sh              # Linux 打包脚本
├── build_windows.bat           # Windows 打包脚本
├── requirements.txt            # Python 依赖
└── .env.example                # 环境变量模板
```

---

## ⚙️ 开发者：从源码运行

```bash
# 1. 克隆
git clone https://github.com/taoge1/acme-portal.git
cd acme-portal

# 2. 安装依赖
pip install -r requirements.txt

# 3. 运行
python3 acme_portal.py

# 4. 打开 http://localhost:10501
```

### 配置 SMTP（可选，用于发送验证码邮件）

编辑 `.env`（参考 `.env.example`）：

```
SMTP_HOST=smtp.qq.com
SMTP_PORT=465
SMTP_USER=your_email@qq.com
SMTP_PASS=your_smtp_password
SMTP_FROM=your_email@qq.com
```

不配置 SMTP 也能签发证书，只是用户登录只能用密码模式。

---

## 📸 截图

<!-- 建议在此添加截图 -->

---

## 🤝 贡献

欢迎提 Issue 和 Pull Request！

---

## 📄 许可证

[MIT](LICENSE)

---

## 🙏 致谢

- [Let's Encrypt](https://letsencrypt.org/) — 免费 SSL 证书
- [acme](https://github.com/certbot/certbot) — ACME 客户端库
- [Flask](https://flask.palletsprojects.com/) — Python Web 框架
