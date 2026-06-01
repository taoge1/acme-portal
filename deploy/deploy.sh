#!/bin/bash
# acme_dns01 令牌化管理门户 一键部署脚本
# 用法：在远程服务器 /opt/acme-dns01/ 目录下执行

set -e

cd /opt/acme-dns01/

# 1. 检查 portal.py 是否存在（从本地上传后替换）
if [ ! -f acme_portal.py ]; then
    echo "[✗] 请先将 acme_portal.py 和 templates/portal.html 上传到本目录"
    exit 1
fi

# 2. 检查依赖
pip3 install flask cryptography acme josepy requests 2>/dev/null
echo "[✓] 依赖检查完成"

# 3. 备份旧模板（可选）
if [ -f templates/index.html ]; then
    cp templates/index.html templates/index.html.bak
    echo "[✓] 备份旧模板"
fi

# 4. 创建新页面软链接或替换
# 让 /acme/ 指向 portal.html
cat > templates/index.html << 'HTML_EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SSL 证书系统</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:20px}
.container{text-align:center;max-width:500px}
h1{color:#38bdf8;font-size:24px;margin-bottom:8px}
p{color:#64748b;font-size:14px;margin-bottom:24px}
.links{display:flex;flex-direction:column;gap:12px}
a{display:block;padding:14px 20px;border-radius:10px;text-decoration:none;font-size:15px;font-weight:600;transition:all.15s}
a.portal{background:#0284c7;color:white}
a.portal:hover{background:#0369a1}
a.legacy{background:#1e293b;border:1px solid #334155;color:#94a3b8}
a.legacy:hover{background:#334155;color:#e2e8f0}
.hint{color:#64748b;font-size:12px;margin-top:24px}
</style>
</head>
<body>
<div class="container">
<h1>🔒 SSL 证书管理系统</h1>
<p>Let's Encrypt DNS-01</p>
<div class="links">
<a class="portal" href="/acme/portal/">📊 管理面板（需登录）</a>
<a class="legacy" href="/acme/legacy/">⚡ 快速签发（无需登录）</a>
</div>
<p class="hint">管理面板每个用户只能看到自己的证书</p>
</div>
</body>
</html>
HTML_EOF
echo "[✓] 新首页已部署"

# 5. 复制 portal.html 到 templates 目录
if [ -f templates/portal.html ]; then
    echo "[✓] portal.html 已存在"
fi

# 6. 停掉旧服务，启动新服务
systemctl stop acme-dns01 2>/dev/null || true

# 创建新 systemd 服务文件（带 SMTP 配置）
cat > /etc/systemd/system/acme-portal.service << 'SVC'
[Unit]
Description=ACME SSL Certificate Portal
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/acme-dns01
ExecStart=/usr/bin/python3 /opt/acme-dns01/acme_portal.py 10501
Restart=always
RestartSec=5
User=root
Environment=SMTP_HOST=smtp.qq.com
Environment=SMTP_PORT=465
Environment=SMTP_USER=xiexianshen@foxmail.com
Environment=SMTP_PASS=zpkvtpsovhbqdhdh
Environment=SMTP_FROM=xiexianshen@foxmail.com

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable --now acme-portal
echo "[✓] acme-portal 服务已启动（端口 10501）"

# 7. 更新 Nginx 配置添加 portal 子路径
NGINX_CONF=/etc/nginx/conf.d/yumingzhengshu.byfwwwg.cn.conf
if grep -q "location /acme/portal/" "$NGINX_CONF" 2>/dev/null; then
    echo "[✓] Nginx portal location 已存在"
else
    sed -i '/location \/acme\//a\\n    location /acme/portal/ {\n        proxy_pass http://127.0.0.1:10501/;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }\n\n    location /acme/legacy/ {\n        proxy_pass http://127.0.0.1:10500/;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }' "$NGINX_CONF"
    nginx -t && nginx -s reload
    echo "[✓] Nginx 配置已更新"
fi

# 8. 让 portal 导入已有证书
sleep 2
curl -s http://127.0.0.1:10501/ > /dev/null
echo "[✓] 管理门户就绪"
echo ""
echo "========================================"
echo "  部署完成！"
echo "========================================"
echo "  管理面板: https://yumingzhengshu.byfwwwg.cn/acme/portal/"
echo "  快速签发: https://yumingzhengshu.byfwwwg.cn/acme/legacy/"
echo "  原接口:   https://yumingzhengshu.byfwwwg.cn/acme/"
echo "========================================"
