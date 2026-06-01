# ACME SSL 证书管理门户

> 🚀 基于 Let's Encrypt DNS-01 验证的免费 SSL 证书自动签发管理平台

一键签发、多用户管理、额度控制、美观界面。支持泛域名、批量签发、7 天到期提醒。

![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.0-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## ✨ 功能一览

### 🎫 证书管理
- **Let's Encrypt DNS-01 验证** — 支持 `*.example.com` 泛域名证书
- **一键签发** — 输入域名，生成 DNS TXT 记录，等待验证完成即签发
- **批量签发** — 一次输入多个域名，各域名独立签发，不是 SAN
- **下载** — 证书/私钥/打包下载（带 JWT 鉴权）
- **到期监控** — 到期前 7 天自动标红提醒
- **用户可删除** — 用户自行管理自己的证书

### 🔐 多用户系统
- **多种登录方式** — 邮箱验证码登录 / 密码登录，登录页默认密码模式
- **额度控制** — 每个用户可设置签发上限（-1 = 无限）
- **管理员面板** — 查看所有证书、管理用户、切换身份模拟登录
- **JWT 鉴权** — Token 7 天有效

### 🎨 界面
- 毛玻璃效果（Glassmorphism）
- 二次元风下雨动画（雨丝 + 底部雾气 + 水花）
- 暗色微紫主题 `#1a1a2e`
- 响应式设计

---

## 🏗 技术栈

| 层级 | 技术 |
|------|------|
| 后端 | Flask 2.0 + Python 3.6+ |
| 前端 | 纯 HTML/CSS/JS SPA（零框架） |
| 证书 | Let's Encrypt / ACME v2 (acme 3.0 + josepy) |
| 数据库 | SQLite (WAL 模式) |
| 验证码 | SMTP (QQ邮箱) |
| 部署 | Nginx 反向代理 + systemd |

```
用户浏览器
    │
    ▼ HTTPS
Nginx (yumingzhengshu.byfwwwg.cn)
    │ /acme/ → proxy_pass http://127.0.0.1:10501/
    ▼
Flask acme_portal.py (端口 10501)
    │
    ├── SQLite → 用户/证书/验证码
    ├── ACME v2 → Let's Encrypt
    └── SMTP → 验证码邮件
```

---

## 🚀 快速开始

### 1. 克隆

```bash
git clone https://github.com/你的用户名/acme-portal.git
cd acme-portal
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 配置环境变量

复制 `.env.example` 为 `.env`，填入你的 SMTP 信息：

```bash
cp .env.example .env
# 编辑 .env，填入 QQ 邮箱 SMTP 信息
```

### 4. 运行

```bash
python3 acme_portal.py
```

默认监听 `0.0.0.0:10501`，浏览器打开 `http://localhost:10501` 即可。

> ⚠️ **生产环境请使用 Nginx 反向代理 + HTTPS**
> 参考 [部署文档](docs/PROJECT.md) 配置 systemd 服务

---

## 📁 项目结构

```
acme-portal/
├── acme_portal.py              # 主力后端 Flask 应用
├── templates/
│   └── portal.html             # 前端 SPA（单文件应用）
├── state/                      # 运行时数据（不入库）
│   └── .gitkeep
├── deploy/
│   └── acme-portal.service     # systemd 服务文件示例
├── archive/                    # 旧版代码归档
├── docs/
│   └── PROJECT.md              # 完整项目文档
├── .env.example                # 环境变量模板
├── requirements.txt            # Python 依赖
├── .gitignore
└── LICENSE                     # MIT
```

---

## 🔧 管理后台

| 功能 | 说明 |
|------|------|
| 管理员账号 | 第一个注册的用户自动成为管理员，或手动修改数据库 |
| 额度管理 | 用户管理 → 设置额度（-1 = 无限） |
| 切换身份 | 管理员可模拟登录任意用户（用于调试） |
| 删除用户 | 同步清除该用户所有证书记录 |

---

## 📸 截图

<!-- 建议在此添加截图 -->
> 运行后截图替换此处

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
