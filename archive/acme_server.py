#!/usr/bin/env python3
"""
ACME DNS-01 Web 控制台 v3
=========================
非阻塞验证 + 独立轮询端点 + 下载 + 邮件
"""

import json, os, time, hashlib, threading, smtplib, io, zipfile
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, render_template, request, jsonify, send_file, Response

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, load_pem_private_key,
)
from cryptography.hazmat.primitives import hashes as crypto_hashes

from acme import client, challenges
from acme.client import ClientNetwork
from acme.messages import (
    Registration, RegistrationResource, Order, OrderResource,
    AuthorizationResource, ChallengeBody, Directory, Authorization,
)
from acme.challenges import DNS01Response
from acme.crypto_util import make_csr
import josepy as jose
import requests

DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
STATE_ROOT = Path("state")
STATE_ROOT.mkdir(exist_ok=True)
ACCOUNT_KEY_PATH = STATE_ROOT / "account_key.pem"

app = Flask(__name__)

# 正在进行的验证任务
_running_verifications: dict[str, threading.Thread] = {}


def _load_account_key():
    if ACCOUNT_KEY_PATH.exists():
        return load_pem_private_key(ACCOUNT_KEY_PATH.read_bytes(), password=None)
    key = rsa.generate_private_key(65537, 4096)
    ACCOUNT_KEY_PATH.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    return key


def _load_or_create_domain_key(state_dir: Path):
    dk_path = state_dir / "domain_key.pem"
    if dk_path.exists():
        return load_pem_private_key(dk_path.read_bytes(), password=None)
    key = rsa.generate_private_key(65537, 2048)
    dk_path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    return key


def _make_engine(domain: str) -> tuple:
    """创建 ACME 客户端并恢复账户"""
    ak = _load_account_key()
    jwk = jose.JWKRSA(key=ak)
    net = ClientNetwork(key=jwk, user_agent="acme-web-v2/1.0")
    d = Directory.from_json(net.get(DIRECTORY_URL).json())
    cli = client.ClientV2(d, net=net)
    # 恢复账户 kid
    resp = net.post(d.newAccount, Registration(only_return_existing=True, terms_of_service_agreed=True))
    data = resp.json()
    regr = RegistrationResource(body=Registration.from_json(data), uri=resp.headers.get('Location', ''))
    cli.query_registration(regr)
    return ak, jwk, net, cli


# ════════════════════════ 路由 ════════════════════════


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/generate", methods=["POST"])
def api_generate():
    data = request.get_json()
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "请输入域名"}), 400

    sdir = STATE_ROOT / domain
    sdir.mkdir(parents=True, exist_ok=True)
    sf = sdir / "state.json"

    # ⚠️ 关键：如果已有 pending/verifying 的订单，复用它的 TXT 值（防止重复生成导致值变化）
    if sf.exists():
        existing = json.loads(sf.read_text())
        if existing.get("status") in ("challenge_generated", "verifying"):
            def get_zone(domain):
                clean = domain.lstrip('*.')
                labels = clean.split('.')
                if len(labels) >= 3 and labels[-2] in ('com', 'net', 'org', 'gov', 'edu', 'co'):
                    return '.'.join(labels[-3:])
                if len(labels) >= 2:
                    return '.'.join(labels[-2:])
                return clean
            zone = get_zone(domain)
            host_record = existing["dns_txt_name"]
            if host_record.endswith(f".{zone}"):
                host_record = host_record[:-len(f".{zone}")]
            return jsonify({
                "domain": domain,
                "host_record": host_record,
                "txt_name": existing["dns_txt_name"],
                "txt_value": existing["dns_txt_value"],
                "status": existing["status"],
            })

    try:
        ak, jwk, net, cli = _make_engine(domain)
        dk = _load_or_create_domain_key(sdir)
        dk_pem = dk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        csr_pem = make_csr(dk_pem, [domain])
        order = cli.new_order(csr_pem)
        authz = order.authorizations[0]

        cb = next((c for c in authz.body.challenges if c.chall.typ == "dns-01"), None)
        if not cb:
            return jsonify({"error": "未找到 DNS-01 challenge"}), 500

        # 对于通配符域名 *.example.com，ACME authorization 的 identifier 是 example.com
        # 用 authz 返回的 identifier 构造 TXT 名，而不是原始domain
        authz_domain = authz.body.identifier.value
        txt_name_full = f"_acme-challenge.{authz_domain}"
        txt_value = cb.chall.validation(jwk)

        # 计算阿里云 DNS 主机记录（去掉 zone 后缀）
        # 例如 txt = _acme-challenge.mall.byfwwwg.cn, zone = byfwwwg.cn → host = _acme-challenge.mall
        def get_zone(domain):
            clean = domain.lstrip('*.')
            labels = clean.split('.')
            # 两段式 TLD: com.cn, net.cn, co.uk 等
            if len(labels) >= 3 and labels[-2] in ('com', 'net', 'org', 'gov', 'edu', 'co'):
                return '.'.join(labels[-3:])
            if len(labels) >= 2:
                return '.'.join(labels[-2:])
            return clean
        zone = get_zone(domain)
        host_record = txt_name_full
        if host_record.endswith(f".{zone}"):
            host_record = host_record[:-len(f".{zone}")]

        state = {
            "domain": domain, "order_uri": order.uri,
            "authorization_uri": order.authorizations[0].uri,
            "challenge_uri": cb.uri,
            "challenge_token": cb.chall.encode("token"),
            "dns_txt_name": txt_name_full, "dns_txt_value": txt_value,
            "status": "challenge_generated",
            "created_at": datetime.utcnow().isoformat(),
        }
        sf.write_text(json.dumps(state, indent=2))

        return jsonify({
            "domain": domain, "host_record": host_record,
            "txt_name": txt_name_full, "txt_value": txt_value,
            "status": "challenge_generated"
        })
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@app.route("/api/verify", methods=["POST"])
def api_verify():
    """触发验证（非阻塞），返回当前状态"""
    data = request.get_json()
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "请输入域名"}), 400

    sdir = STATE_ROOT / domain
    sf = sdir / "state.json"
    if not sf.exists():
        return jsonify({"error": "请先生成 challenge", "status": "error"}), 400

    state = json.loads(sf.read_text())

    # 如果已完成，直接返回证书
    if state.get("status") == "completed":
        cert = (sdir / "fullchain.pem").read_text() if (sdir / "fullchain.pem").exists() else state.get("certificate", "")
        priv = (sdir / "domain_key.pem").read_text() if (sdir / "domain_key.pem").exists() else ""
        return jsonify({"status": "completed", "domain": domain, "certificate": cert, "private_key": priv})

    # 如果有正在运行的验证线程，返回当前状态
    if domain in _running_verifications and _running_verifications[domain].is_alive():
        return jsonify({"status": state.get("status", "verifying")})

    # 启动后台验证
    def _verify_bg():
        try:
            state["status"] = "verifying"
            sf.write_text(json.dumps(state, indent=2))

            ak, jwk, net, cli = _make_engine(domain)

            # 获取最新 authz
            authz_body = Authorization.from_json(net.get(state["authorization_uri"]).json())

            if authz_body.status.name != "valid":
                # 回答 challenge
                cb_data = net.get(state["challenge_uri"]).json()
                cb = ChallengeBody.from_json(cb_data)
                cli.answer_challenge(cb, DNS01Response())

                # 轮询
                for _ in range(100):
                    time.sleep(3)
                    authz_body = Authorization.from_json(net.get(state["authorization_uri"]).json())
                    if authz_body.status.name == "valid":
                        break
                    elif authz_body.status.name == "invalid":
                        errs = [f"{c.error.typ}: {c.error.detail}" for c in authz_body.challenges if c.error]
                        state["status"] = "invalid"
                        state["error"] = "; ".join(errs) or "未知错误"
                        sf.write_text(json.dumps(state, indent=2))
                        return
                else:
                    state["status"] = "timeout"
                    sf.write_text(json.dumps(state, indent=2))
                    return

            # 签发
            dk = _load_or_create_domain_key(sdir)
            dk_pem = dk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            csr_pem = make_csr(dk_pem, [domain])

            order_body = Order.from_json(net.get(state["order_uri"]).json())
            order_resource = OrderResource(
                body=order_body, uri=state["order_uri"], csr_pem=csr_pem,
                authorizations=[AuthorizationResource(body=authz_body, uri=state["authorization_uri"])],
            )
            deadline = datetime.utcnow() + timedelta(seconds=300)
            try:
                order_resource = cli.finalize_order(order_resource, deadline)
            except Exception:
                pass

            # 下载证书
            od = net.get(state["order_uri"]).json()
            cert_url = od.get("certificate", "")
            if cert_url:
                cert_pem = requests.get(cert_url).text
                (sdir / "fullchain.pem").write_text(cert_pem)
                state["certificate"] = cert_pem

            state["status"] = "completed"
            sf.write_text(json.dumps(state, indent=2))
        except Exception as e:
            state["status"] = "error"
            state["error"] = str(e)
            sf.write_text(json.dumps(state, indent=2))
        finally:
            _running_verifications.pop(domain, None)

    t = threading.Thread(target=_verify_bg, daemon=True)
    _running_verifications[domain] = t
    t.start()

    return jsonify({"status": "verifying"})


@app.route("/api/status", methods=["POST"])
def api_status():
    """轮询当前状态"""
    data = request.get_json()
    domain = data.get("domain", "").strip()
    sdir = STATE_ROOT / domain
    sf = sdir / "state.json"
    if not sf.exists():
        return jsonify({"status": "not_found"})

    state = json.loads(sf.read_text())
    if state.get("status") == "completed":
        cert = (sdir / "fullchain.pem").read_text() if (sdir / "fullchain.pem").exists() else state.get("certificate", "")
        priv = (sdir / "domain_key.pem").read_text() if (sdir / "domain_key.pem").exists() else ""
        return jsonify({"status": "completed", "domain": domain, "certificate": cert, "private_key": priv})

    return jsonify({
        "status": state.get("status", "unknown"),
        "error": state.get("error", ""),
    })


@app.route("/api/download/<domain>/<filetype>")
def api_download(domain, filetype):
    """下载证书或私钥文件"""
    sdir = STATE_ROOT / domain
    if filetype == "cert":
        path = sdir / "fullchain.pem"
        fname = f"{domain}_cert.pem"
    elif filetype == "key":
        path = sdir / "domain_key.pem"
        fname = f"{domain}_key.pem"
    elif filetype == "all":
        # ZIP 打包
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            for fn, rn in [("fullchain.pem", f"{domain}_cert.pem"), ("domain_key.pem", f"{domain}_key.pem")]:
                fp = sdir / fn
                if fp.exists():
                    zf.write(str(fp), rn)
        buf.seek(0)
        return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=f"{domain}_ssl.zip")
    else:
        return jsonify({"error": "未知文件类型"}), 400

    if not path.exists():
        return jsonify({"error": "文件不存在"}), 404
    return send_file(str(path), mimetype="application/x-pem-file", as_attachment=True, download_name=fname)


@app.route("/api/email", methods=["POST"])
def api_email():
    """发送证书到邮箱"""
    data = request.get_json()
    domain = data.get("domain", "").strip()
    email = data.get("email", "").strip()
    if not domain or not email:
        return jsonify({"error": "缺少域名或邮箱"}), 400

    sdir = STATE_ROOT / domain
    cert_path = sdir / "fullchain.pem"
    key_path = sdir / "domain_key.pem"
    if not cert_path.exists():
        return jsonify({"error": "证书文件不存在"}), 404

    # SMTP 配置 — 使用阿里云 DirectMail 或任意 SMTP
    smtp_host = os.environ.get("SMTP_HOST", "")
    smtp_port = int(os.environ.get("SMTP_PORT", "465"))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")
    smtp_from = os.environ.get("SMTP_FROM", smtp_user)

    if not smtp_host:
        return jsonify({"error": "SMTP 未配置，请联系管理员设置 SMTP_HOST 环境变量"}), 500

    try:
        msg = MIMEMultipart()
        msg["Subject"] = f"SSL 证书 - {domain}"
        msg["From"] = smtp_from
        msg["To"] = email
        msg.attach(MIMEText(
            f"您好，\n\n以下是域名 {domain} 的 SSL 证书和私钥，请妥善保管。\n\n"
            f"证书有效期：90 天\n颁发机构：Let's Encrypt\n\n附件：\n"
            f"  - {domain}_cert.pem （证书/公钥）\n"
            f"  - {domain}_key.pem （私钥）\n",
            "plain", "utf-8"
        ))

        for path, rname in [(cert_path, f"{domain}_cert.pem"), (key_path, f"{domain}_key.pem")]:
            part = MIMEBase("application", "x-pem-file")
            part.set_payload(path.read_text())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename={rname}")
            msg.attach(part)

        with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, [email], msg.as_string())

        return jsonify({"status": "sent", "message": f"证书已发送到 {email}"})
    except Exception as e:
        return jsonify({"error": f"邮件发送失败: {e}"}), 500


if __name__ == "__main__":
    os.makedirs("templates", exist_ok=True)
    app.run(host="0.0.0.0", port=10500, debug=False, threaded=True)
