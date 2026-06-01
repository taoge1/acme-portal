#!/usr/bin/env python3
"""
ACME 证书管理门户 v1
=====================
基于 acme_server.py 的升级版：
  - 邮箱+验证码登录/注册
  - 证书管理面板（列表+状态+到期提醒）
  - 集成原有 ACME 签发功能

运行：python3 acme_portal.py [port]
默认端口：10501
"""

import json, os, time, re, hmac, hashlib, base64, threading, smtplib
import io, zipfile, sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

import requests
from flask import (
    Flask, render_template, request, jsonify, send_file, Response,
    make_response, g,
)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, load_pem_private_key,
)
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography import x509

from acme import client, challenges
from acme.client import ClientNetwork
from acme.messages import (
    Registration, RegistrationResource, Order, OrderResource,
    AuthorizationResource, ChallengeBody, Directory, Authorization,
)
from acme.challenges import DNS01Response
from acme.crypto_util import make_csr
import josepy as jose

# ════════════════════════ 配置 ════════════════════════

JWT_SECRET = os.environ.get("PORTAL_JWT_SECRET", "")
if not JWT_SECRET:
    JWT_SECRET = hashlib.sha256(os.urandom(64)).hexdigest()
    print(f"[*] 自动生成 JWT_SECRET: {JWT_SECRET[:16]}...")
    print("  可通过环境变量 PORTAL_JWT_SECRET 设置固定值")

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)
VERIFY_CODE_EXPIRE = 600       # 10分钟
SEND_COOLDOWN = 60             # 两次发送间隔(秒)
JWT_EXPIRE = 86400 * 7

# 超级管理员配置
# 管理员账号配置
# 优先级：环境变量 > 内置默认值（仅用于 exe 首次启动）
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
STATE_ROOT = Path("state")
STATE_ROOT.mkdir(exist_ok=True)
ACCOUNT_KEY_PATH = STATE_ROOT / "account_key.pem"
DB_PATH = STATE_ROOT / "portal.db"

app = Flask(__name__)

# ════════════════════════ 数据库 ════════════════════════

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(str(DB_PATH))
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT DEFAULT '',
            password_hash TEXT DEFAULT '',
            is_admin INTEGER DEFAULT 0,
            max_certs INTEGER DEFAULT 5,
            total_issued INTEGER DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_login TEXT
        );
        CREATE TABLE IF NOT EXISTS verify_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            code TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            issued_at TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            notes TEXT DEFAULT '',
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_user_domain ON certificates(user_id, domain);
    """)
    db.commit()
    # 迁移
    for col, typ in [('password_hash', "TEXT DEFAULT ''"),
                     ('is_admin', 'INTEGER DEFAULT 0'),
                     ('max_certs', 'INTEGER DEFAULT 5'),
                     ('total_issued', 'INTEGER DEFAULT 0')]:
        try:
            db.execute(f"ALTER TABLE users ADD COLUMN {col} {typ}")
            db.commit()
        except: pass
    db.close()
    print("[✓] 数据库初始化完成")

def backfill_expires():
    """扫描已有证书文件，回填 expires_at"""
    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row
    updated = 0
    for row in db.execute("SELECT id,domain,expires_at FROM certificates WHERE expires_at IS NULL").fetchall():
        sdir = STATE_ROOT / row["domain"]
        fp = sdir / "fullchain.pem"
        if fp.exists():
            try:
                cert = x509.load_pem_x509_certificate(fp.read_bytes())
                exp = cert.not_valid_after.isoformat()
                db.execute("UPDATE certificates SET expires_at=? WHERE id=?",(exp,row["id"]))
                updated += 1
            except: pass
    if updated:
        db.commit()
        print(f"[✓] 回填了 {updated} 个证书的到期时间")
    db.close()

def seed_admin():
    """确保超级管理员账号存在"""
    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row
    user = db.execute("SELECT * FROM users WHERE email=?", (ADMIN_EMAIL,)).fetchone()
    if not user:
        pwd = hash_password(ADMIN_PASSWORD)
        db.execute(
            "INSERT INTO users(email,password_hash,is_admin,max_certs) VALUES(?,?,1,-1)",
            (ADMIN_EMAIL, pwd)
        )
        db.commit()
        print(f"[✓] 超级管理员已创建: {ADMIN_EMAIL}")
    else:
        # 确保管理员标记和无限额度
        db.execute("UPDATE users SET is_admin=1, max_certs=-1 WHERE email=? AND (is_admin=0 OR max_certs!=-1)",
                   (ADMIN_EMAIL,))
        db.commit()
    db.close()


# ════════════════════════ JWT ════════════════════════

def jwt_encode(payload: dict, expire_seconds: int = JWT_EXPIRE) -> str:
    payload = payload.copy()
    payload["iat"] = int(time.time())
    payload["exp"] = int(time.time()) + expire_seconds
    header = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig = hmac.new(JWT_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"

def jwt_decode(token: str):
    try:
        parts = token.split(".")
        if len(parts) != 3: return None
        sig_check = hmac.new(JWT_SECRET.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(base64.urlsafe_b64encode(sig_check).rstrip(b"=").decode(), parts[2]): return None
        body = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        if body.get("exp", 0) < time.time(): return None
        return body
    except: return None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error":"未登录"}), 401
        payload = jwt_decode(auth[7:])
        if not payload:
            return jsonify({"error":"登录已过期，请重新登录"}), 401
        g.user_id = payload["user_id"]
        g.user_email = payload["email"]
        g.is_admin = payload.get("is_admin", False)
        return f(*args, **kwargs)
    return decorated


# ════════════════════════ 验证码 ════════════════════════

def generate_code() -> str:
    return str(os.urandom(4).hex())[-6:]

def hash_password(password: str) -> str:
    """SHA256 密码哈希"""
    salt = "acme_portal_salt_v1"
    return hashlib.sha256((salt + password).encode()).hexdigest()

def send_verify_email(to_email: str, code: str) -> bool:
    if not SMTP_HOST:
        return True  # 开发模式
    try:
        msg = MIMEText(f"您的验证码是：{code}\n\n有效期10分钟，请勿泄露。\n—— SSL证书管理平台","plain","utf-8")
        msg["Subject"] = f"登录验证码：{code}"
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_FROM,[to_email],msg.as_string())
        return True
    except Exception as e:
        print(f"[✗] 邮件发送失败: {e}")
        return False

def is_valid_email(email: str) -> bool:
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email))


# ════════════════════════ ACME 引擎 ════════════════════════

def _load_account_key():
    if ACCOUNT_KEY_PATH.exists():
        return load_pem_private_key(ACCOUNT_KEY_PATH.read_bytes(), password=None)
    key = rsa.generate_private_key(65537, 4096)
    ACCOUNT_KEY_PATH.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    return key

def _load_or_create_domain_key(sdir: Path):
    dk = sdir / "domain_key.pem"
    if dk.exists():
        return load_pem_private_key(dk.read_bytes(), password=None)
    key = rsa.generate_private_key(65537, 2048)
    dk.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    return key

def _make_engine(domain: str) -> tuple:
    ak = _load_account_key()
    jwk = jose.JWKRSA(key=ak)
    net = ClientNetwork(key=jwk, user_agent="acme-web-v2/1.0")
    d = Directory.from_json(net.get(DIRECTORY_URL).json())
    cli = client.ClientV2(d, net=net)
    resp = net.post(d.newAccount, Registration(only_return_existing=True,terms_of_service_agreed=True), acme_version=2)
    data = resp.json()
    regr = RegistrationResource(body=Registration.from_json(data),uri=resp.headers.get('Location',''))
    cli.query_registration(regr)
    return ak, jwk, net, cli

def get_zone(domain: str) -> str:
    clean = domain.lstrip('*.')
    labels = clean.split('.')
    if len(labels)>=3 and labels[-2] in ('com','net','org','gov','edu','co'):
        return '.'.join(labels[-3:])
    if len(labels)>=2: return '.'.join(labels[-2:])
    return clean

_running = {}  # type: ignore

def _ensure_cert_record(db, uid, domain, state):
    """创建或更新数据库中的证书记录（total_issued 已在生成时递增，此处不再重复加）"""
    expires_at = None
    cert_text = state.get("certificate","")
    if cert_text:
        try:
            start = cert_text.find("-----BEGIN CERTIFICATE-----")
            end = cert_text.find("-----END CERTIFICATE-----")
            if start>=0 and end>=0:
                single = cert_text[start:end+len("-----END CERTIFICATE-----")]
                cert_obj = x509.load_pem_x509_certificate(single.encode())
                expires_at = cert_obj.not_valid_after.isoformat()
        except: pass
    try:
        db.execute(
            "INSERT INTO certificates(user_id,domain,status,issued_at,expires_at,created_at) "
            "VALUES(?,?,'valid',?,?,datetime('now')) "
            "ON CONFLICT(user_id,domain) DO UPDATE SET status='valid',expires_at=COALESCE(?,expires_at)",
            (uid,domain,state.get("completed_at",""),expires_at,expires_at)
        )
        db.commit()
    except: pass


# ════════════════════════ 认证路由 ════════════════════════

@app.route("/api/auth/send_code", methods=["POST"])
def api_auth_send_code():
    data = request.get_json()
    email = (data.get("email","") or "").strip().lower()
    if not is_valid_email(email):
        return jsonify({"error":"请输入有效的邮箱地址"}), 400
    db = get_db()
    # 发送冷却检查
    recent = db.execute(
        "SELECT created_at FROM verify_codes WHERE email=? ORDER BY created_at DESC LIMIT 1",
        (email,)
    ).fetchone()
    if recent:
        try:
            last_dt = datetime.strptime(recent["created_at"], "%Y-%m-%d %H:%M:%S")
            elapsed = (datetime.utcnow() - last_dt).total_seconds()
            if elapsed < SEND_COOLDOWN:
                wait = int(SEND_COOLDOWN - elapsed)
                return jsonify({"error":f"发送太频繁，请 {wait} 秒后重试"}), 429
        except: pass
    code = generate_code()
    expires_at = (datetime.utcnow()+timedelta(seconds=VERIFY_CODE_EXPIRE)).isoformat()
    db.execute("INSERT INTO verify_codes(email,code,expires_at) VALUES(?,?,?)",(email,code,expires_at))
    db.commit()
    if not send_verify_email(email, code):
        if not SMTP_HOST:
            return jsonify({"status":"code_sent","debug_code":code})
        return jsonify({"error":"验证码发送失败"}), 500
    if not SMTP_HOST:
        return jsonify({"status":"code_sent","debug_code":code,"hint":"开发模式"})
    return jsonify({"status":"code_sent","message":f"验证码已发送到 {email}"})


@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    data = request.get_json()
    email = (data.get("email","") or "").strip().lower()
    code = (data.get("code","") or "").strip()
    password = (data.get("password","") or "").strip()
    if not is_valid_email(email): return jsonify({"error":"邮箱无效"}), 400
    db = get_db()
    if password:
        # 密码登录
        user = db.execute("SELECT * FROM users WHERE email=? AND password_hash!=''",(email,)).fetchone()
        if not user: return jsonify({"error":"该账号未设置密码，请使用验证码登录"}), 400
        expected = hash_password(password)
        if not hmac.compare_digest(expected, user["password_hash"]):
            return jsonify({"error":"密码错误"}), 400
        db.execute("UPDATE users SET last_login=datetime('now') WHERE id=?",(user["id"],))
        db.commit()
    else:
        if not code: return jsonify({"error":"请输入验证码或密码"}), 400
        # 验证码登录（不区分大小写）
        row = db.execute(
            "SELECT * FROM verify_codes WHERE email=? AND LOWER(code)=LOWER(?) AND used=0 AND expires_at>datetime('now') ORDER BY created_at DESC LIMIT 1",
            (email,code)
        ).fetchone()
        if not row: return jsonify({"error":"验证码无效或已过期"}), 400
        db.execute("UPDATE verify_codes SET used=1 WHERE id=?",(row["id"],))
        user = db.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
        if not user:
            db.execute("INSERT INTO users(email,last_login) VALUES(?,datetime('now'))",(email,))
            db.commit()
            user = db.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
            _scan_existing_for_user(db, user["id"])
        else:
            db.execute("UPDATE users SET last_login=datetime('now') WHERE id=?",(user["id"],))
            db.commit()
    token = jwt_encode({"user_id":user["id"],"email":user["email"],"is_admin":bool(user["is_admin"])})
    has_pwd = bool(user["password_hash"])
    is_admin = bool(user["is_admin"])
    return jsonify({"token":token,"user":{"id":user["id"],"email":user["email"],"has_password":has_pwd,"is_admin":is_admin}})

def _scan_existing_for_user(db, uid):
    """为新用户扫描已有证书"""
    added = 0
    for sdir in STATE_ROOT.iterdir():
        if not sdir.is_dir(): continue
        sf = sdir / "state.json"
        if not sf.exists(): continue
        domain = sdir.name
        try: state = json.loads(sf.read_text())
        except: continue
        if state.get("status") == "completed":
            _ensure_cert_record(db, uid, domain, state)
            added += 1
    if added: print(f"[*] 为用户 #{uid} 导入了 {added} 个已有证书")


@app.route("/api/auth/me", methods=["GET"])
@require_auth
def api_auth_me():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?",(g.user_id,)).fetchone()
    if not user: return jsonify({"error":"用户不存在"}), 404
    is_admin = bool(user["is_admin"])
    cert_count = user["total_issued"] if not is_admin else db.execute("SELECT COUNT(*) as c FROM certificates",()).fetchone()["c"]
    max_certs = user["max_certs"]
    if is_admin:
        stats = db.execute(
            "SELECT COUNT(*) as total,"
            "SUM(CASE WHEN status='valid' THEN 1 ELSE 0 END) as valid,"
            "SUM(CASE WHEN status='expiring_soon' THEN 1 ELSE 0 END) as expiring_soon,"
            "SUM(CASE WHEN status='expired' THEN 1 ELSE 0 END) as expired,"
            "SUM(CASE WHEN status IN ('invalid','pending') THEN 1 ELSE 0 END) as other "
            "FROM certificates"
        ).fetchone()
    else:
        stats = db.execute(
            "SELECT COUNT(*) as total,"
            "SUM(CASE WHEN status='valid' THEN 1 ELSE 0 END) as valid,"
            "SUM(CASE WHEN status='expiring_soon' THEN 1 ELSE 0 END) as expiring_soon,"
            "SUM(CASE WHEN status='expired' THEN 1 ELSE 0 END) as expired,"
            "SUM(CASE WHEN status IN ('invalid','pending') THEN 1 ELSE 0 END) as other "
            "FROM certificates WHERE user_id=?",(g.user_id,)
        ).fetchone()
    return jsonify({"user":{"email":user["email"],"has_password":bool(user["password_hash"]),"is_admin":is_admin,"max_certs":max_certs,"cert_count":cert_count},"stats":dict(stats)})

@app.route("/api/auth/set_password", methods=["POST"])
@require_auth
def api_auth_set_password():
    """设置或修改密码"""
    data = request.get_json()
    password = (data.get("password","") or "").strip()
    if len(password) < 6:
        return jsonify({"error":"密码至少6位"}), 400
    db = get_db()
    db.execute("UPDATE users SET password_hash=? WHERE id=?",
               (hash_password(password), g.user_id))
    db.commit()
    return jsonify({"status":"ok","message":"密码已设置"})


# ════════════════════════ 证书管理 ════════════════════════

def update_cert_statuses():
    db = get_db()
    now = datetime.utcnow()
    for row in db.execute("SELECT id,expires_at,status FROM certificates WHERE status IN ('valid','expiring_soon')"):
        if not row["expires_at"]: continue
        try:
            exp = datetime.fromisoformat(row["expires_at"])
            days = (exp-now).days
            ns = "expired" if days < 0 else ("expiring_soon" if days <= 7 else "valid")
            if ns != row["status"]:
                db.execute("UPDATE certificates SET status=? WHERE id=?",(ns,row["id"]))
        except: pass
    db.commit()


@app.route("/api/certs", methods=["GET"])
@require_auth
def api_list_certs():
    update_cert_statuses()
    db = get_db()
    if g.is_admin:
        rows = db.execute("SELECT * FROM certificates ORDER BY created_at DESC").fetchall()
    else:
        rows = db.execute("SELECT * FROM certificates WHERE user_id=? ORDER BY created_at DESC",(g.user_id,)).fetchall()
    certs = []
    for r in rows:
        d = dict(r)
        if d["expires_at"]:
            try:
                exp = datetime.fromisoformat(d["expires_at"])
                d["days_remaining"] = max((exp-datetime.utcnow()).days, 0)
            except: d["days_remaining"] = None
        else: d["days_remaining"] = None
        certs.append(d)
    stats = {"total":len(certs),"valid":0,"expiring_soon":0,"expired":0,"failed":0,"pending":0}
    for c in certs: stats[c.get("status","pending")] = stats.get(c.get("status","pending"),0)+1
    return jsonify({"certs":certs,"stats":stats})


@app.route("/api/certs/<int:cid>", methods=["GET"])
@require_auth
def api_get_cert(cid):
    db = get_db()
    if g.is_admin:
        row = db.execute("SELECT * FROM certificates WHERE id=?",(cid,)).fetchone()
    else:
        row = db.execute("SELECT * FROM certificates WHERE id=? AND user_id=?",(cid,g.user_id)).fetchone()
    if not row: return jsonify({"error":"证书不存在"}), 404
    domain = row["domain"]
    sdir = STATE_ROOT / domain
    sf = sdir / "state.json"
    ret = {"cert":dict(row),"pem":{},"files_exist":False}
    if sf.exists():
        state = json.loads(sf.read_text())
        ret["pem"]["certificate"] = state.get("certificate","")
        kp = sdir / "domain_key.pem"
        if kp.exists(): ret["pem"]["private_key"] = kp.read_text()
        ret["files_exist"] = True
    return jsonify(ret)


@app.route("/api/certs/<int:cid>/download/<ft>")
@require_auth
def api_download_cert(cid, ft):
    db = get_db()
    if g.is_admin:
        row = db.execute("SELECT * FROM certificates WHERE id=?",(cid,)).fetchone()
    else:
        row = db.execute("SELECT * FROM certificates WHERE id=? AND user_id=?",(cid,g.user_id)).fetchone()
    if not row: return jsonify({"error":"证书不存在"}), 404
    domain = row["domain"]
    sdir = STATE_ROOT / domain
    sf = sdir / "state.json"
    if not sf.exists(): return jsonify({"error":"文件不存在"}), 404
    state = json.loads(sf.read_text())
    if ft == "cert":
        t = state.get("certificate","")
        if not t: return jsonify({"error":"证书为空"}), 404
        return Response(t, mimetype="application/x-pem-file",
                       headers={"Content-Disposition":f"attachment; filename={domain}_cert.pem"})
    elif ft == "key":
        kp = sdir / "domain_key.pem"
        if not kp.exists(): return jsonify({"error":"私钥不存在"}), 404
        return send_file(str(kp), mimetype="application/x-pem-file",
                       as_attachment=True, download_name=f"{domain}_key.pem")
    elif ft == "all":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as z:
            ct = state.get("certificate","")
            if ct: z.writestr(f"{domain}_cert.pem",ct)
            kp = sdir / "domain_key.pem"
            if kp.exists(): z.write(str(kp),f"{domain}_key.pem")
        buf.seek(0)
        return send_file(buf, mimetype="application/zip",
                       as_attachment=True, download_name=f"{domain}_ssl.zip")
    return jsonify({"error":"未知文件类型"}), 400


@app.route("/api/certs/<int:cid>/notes", methods=["PUT"])
@require_auth
def api_update_notes(cid):
    data = request.get_json()
    notes = (data.get("notes","") or "").strip()
    db = get_db()
    if g.is_admin:
        db.execute("UPDATE certificates SET notes=? WHERE id=?",(notes,cid))
    else:
        db.execute("UPDATE certificates SET notes=? WHERE id=? AND user_id=?",(notes,cid,g.user_id))
    db.commit()
    return jsonify({"status":"ok"})


@app.route("/api/certs/<int:cid>", methods=["DELETE"])
@require_auth
def api_delete_cert(cid):
    db = get_db()
    if g.is_admin:
        db.execute("DELETE FROM certificates WHERE id=?",(cid,))
    else:
        db.execute("DELETE FROM certificates WHERE id=? AND user_id=?",(cid,g.user_id))
    db.commit()
    return jsonify({"status":"deleted"})


# ════════════════════════ 管理员路由 ════════════════════════

@app.route("/api/admin/users", methods=["GET"])
@require_auth
def api_admin_users():
    """管理员查看所有用户及其额度"""
    if not g.is_admin:
        return jsonify({"error":"无权限"}), 403
    db = get_db()
    rows = db.execute(
        "SELECT u.id, u.email, u.is_admin, u.max_certs, u.total_issued, u.created_at, u.last_login,"
        "COUNT(c.id) as cert_count "
        "FROM users u LEFT JOIN certificates c ON u.id=c.user_id "
        "GROUP BY u.id ORDER BY u.created_at DESC"
    ).fetchall()
    return jsonify({"users":[dict(r) for r in rows]})

@app.route("/api/admin/users/<int:uid>/quota", methods=["PUT"])
@require_auth
def api_admin_set_quota(uid):
    """设置用户额度"""
    if not g.is_admin:
        return jsonify({"error":"无权限"}), 403
    data = request.get_json()
    max_certs = data.get("max_certs", 5)
    if not isinstance(max_certs, int) or max_certs < -1:
        return jsonify({"error":"额度必须为 -1(无限) 或 正整数"}), 400
    db = get_db()
    db.execute("UPDATE users SET max_certs=? WHERE id=?",(max_certs, uid))
    db.commit()
    return jsonify({"status":"ok","max_certs":max_certs})

@app.route("/api/admin/create_user", methods=["POST"])
@require_auth
def api_admin_create_user():
    """管理员直接创建用户账号"""
    if not g.is_admin:
        return jsonify({"error":"无权限"}), 403
    data = request.get_json()
    email = (data.get("email","") or "").strip().lower()
    password = (data.get("password","") or "").strip()
    max_certs = data.get("max_certs", 5)
    if not is_valid_email(email):
        return jsonify({"error":"请输入有效的邮箱地址"}), 400
    if len(password) < 6:
        return jsonify({"error":"密码至少6位"}), 400
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone()
    if existing:
        return jsonify({"error":"该邮箱已注册","user_id":existing["id"]}), 409
    db.execute(
        "INSERT INTO users(email,password_hash,max_certs) VALUES(?,?,?)",
        (email, hash_password(password), max_certs)
    )
    db.commit()
    user = db.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
    return jsonify({
        "status":"ok",
        "password": password,  # 返回明文以便管理员记录
        "user":{"id":user["id"],"email":user["email"],"max_certs":user["max_certs"]}
    })

@app.route("/api/admin/users/<int:uid>/reset_password", methods=["PUT"])
@require_auth
def api_admin_reset_password(uid):
    """管理员重置用户密码"""
    if not g.is_admin:
        return jsonify({"error":"无权限"}), 403
    data = request.get_json()
    new_password = (data.get("password","") or "").strip()
    if len(new_password) < 6:
        return jsonify({"error":"密码至少6位"}), 400
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
    if not user:
        return jsonify({"error":"用户不存在"}), 404
    db.execute("UPDATE users SET password_hash=? WHERE id=?",
               (hash_password(new_password), uid))
    db.commit()
    return jsonify({"status":"ok","password":new_password,"user":{"id":uid,"email":user["email"]}})

@app.route("/api/admin/users/<int:uid>", methods=["DELETE"])
@require_auth
def api_admin_delete_user(uid):
    """管理员删除用户"""
    if not g.is_admin:
        return jsonify({"error":"无权限"}), 403
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=? AND is_admin=0",(uid,)).fetchone()
    if not user:
        return jsonify({"error":"用户不存在或无法删除管理员"}), 404
    db.execute("DELETE FROM certificates WHERE user_id=?",(uid,))
    db.execute("DELETE FROM verify_codes WHERE email=?",(user["email"],))
    db.execute("DELETE FROM users WHERE id=?",(uid,))
    db.commit()
    return jsonify({"status":"deleted","email":user["email"]})

@app.route("/api/admin/users/<int:uid>/login_as", methods=["POST"])
@require_auth
def api_admin_login_as(uid):
    """管理员切换身份登录为指定用户"""
    if not g.is_admin:
        return jsonify({"error":"无权限"}), 403
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=? AND is_admin=0",(uid,)).fetchone()
    if not user:
        return jsonify({"error":"用户不存在或无法切换管理员"}), 404
    token = jwt_encode({"user_id":user["id"],"email":user["email"],"is_admin":False})
    return jsonify({"token":token,"user":{"id":user["id"],"email":user["email"],"is_admin":False}})


# ════════════════════════ ACME 签发路由 ════════════════════════

@app.route("/api/acme/generate", methods=["POST"])
@require_auth
def api_acme_generate():
    data = request.get_json()
    raw = data.get("domain","").strip()
    if not raw: return jsonify({"error":"请输入域名"}), 400
    # 支持批量：每行一个，或逗号/分号分隔
    domains = [d.strip().lower() for d in re.split(r'[\n;,]+', raw) if d.strip()]
    if not domains: return jsonify({"error":"请输入域名"}), 400
    # 去重
    domains = list(dict.fromkeys(domains))
    
    # 额度检查
    db = get_db()
    if not g.is_admin:
        user = db.execute("SELECT max_certs,total_issued FROM users WHERE id=?",(g.user_id,)).fetchone()
        quota = user["max_certs"] if user else 5
        issued = user["total_issued"] if user else 0
        new_count = len([d for d in domains if not (STATE_ROOT / d / "state.json").exists()])
        if quota >= 0 and issued + new_count > quota:
            return jsonify({"error":f"额度不足（已有{issued}，额度{quota}，本次新增{new_count}）"}), 403
    
    results = []
    for domain in domains:
        sdir = STATE_ROOT / domain
        sdir.mkdir(parents=True, exist_ok=True)
        sf = sdir / "state.json"
        if sf.exists():
            existing = json.loads(sf.read_text())
            if existing.get("status") in ("challenge_generated","verifying"):
                zone = get_zone(domain)
                hr = existing["dns_txt_name"]
                if hr.endswith(f".{zone}"): hr = hr[:-len(f".{zone}")]
                results.append({"domain":domain,"host_record":hr,"txt_name":existing["dns_txt_name"],
                               "txt_value":existing["dns_txt_value"],"status":existing["status"]})
                continue
            if existing.get("status") == "completed" or (sdir/"fullchain.pem").exists():
                # 已签发完成，返回已有信息，不创建新订单
                results.append({"domain":domain,"status":"completed","host_record":"已签发",
                               "txt_name":"","txt_value":""})
                continue
        try:
            ak,jwk,net,cli = _make_engine(domain)
            dk = _load_or_create_domain_key(sdir)
            dk_pem = dk.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())
            csr_pem = make_csr(dk_pem,[domain])
            order = cli.new_order(csr_pem)
            authz = order.authorizations[0]
            cb = next((c for c in authz.body.challenges if c.chall.typ=="dns-01"), None)
            if not cb:
                results.append({"domain":domain,"error":"未找到 DNS-01 challenge"})
                continue
            tn = f"_acme-challenge.{authz.body.identifier.value}"
            tv = cb.chall.validation(jwk)
            zone = get_zone(domain)
            hr = tn
            if hr.endswith(f".{zone}"): hr = hr[:-len(f".{zone}")]
            state = {"domain":domain,"order_uri":order.uri,"authorization_uri":order.authorizations[0].uri,
                    "challenge_uri":cb.uri,"challenge_token":cb.chall.encode("token"),
                    "dns_txt_name":tn,"dns_txt_value":tv,"status":"challenge_generated",
                    "user_id":g.user_id,"created_at":datetime.utcnow().isoformat()}
            sf.write_text(json.dumps(state, indent=2))
            db.execute("INSERT OR IGNORE INTO certificates(user_id,domain,status,created_at) VALUES(?,?,'pending',datetime('now'))",
                      (g.user_id,domain))
            if db.total_changes > 0:
                db.execute("UPDATE users SET total_issued=total_issued+1 WHERE id=?",(g.user_id,))
            db.commit()
            results.append({"domain":domain,"host_record":hr,"txt_name":tn,"txt_value":tv,"status":"challenge_generated"})
        except Exception as e:
            results.append({"domain":domain,"error":str(e)})
    return jsonify({"domains":results,"total":len(results),"success":sum(1 for r in results if r.get("status")=="challenge_generated")})


@app.route("/api/acme/verify", methods=["POST"])
@require_auth
def api_acme_verify():
    data = request.get_json()
    domain_raw = (data.get("domain","") or "").strip()
    if not domain_raw: return jsonify({"error":"请输入域名"}), 400
    # 支持逗号分隔的批量域名
    domains = [d.strip().lower() for d in re.split(r'[\n;,]+', domain_raw) if d.strip()]
    results = []
    for domain in domains:
        sdir = STATE_ROOT / domain; sf = sdir / "state.json"
        if not sf.exists():
            results.append({"domain":domain,"error":"请先生成 challenge"})
            continue
        state = json.loads(sf.read_text())
        if state.get("status")=="completed" or (sdir/"fullchain.pem").exists():
            cert_text = (sdir/"fullchain.pem").read_text() if (sdir/"fullchain.pem").exists() else state.get("certificate","")
            priv = (sdir/"domain_key.pem").read_text() if (sdir/"domain_key.pem").exists() else ""
            # 修复可能不一致的 state.json
            if state.get("status")!="completed":
                state["status"]="completed"
                state["certificate"]=cert_text
                sf.write_text(json.dumps(state,indent=2))
            db = get_db(); _ensure_cert_record(db,g.user_id,domain,state)
            results.append({"domain":domain,"status":"completed","certificate":cert_text,"private_key":priv})
            continue
        if domain in _running and _running[domain].is_alive():
            results.append({"domain":domain,"status":state.get("status","verifying")})
            continue
        def _mk_verify(domain, state):
            def _verify_bg():
                try:
                    sdir = STATE_ROOT / domain; sf = sdir / "state.json"
                    state["status"]="verifying"; sf.write_text(json.dumps(state,indent=2))
                    with app.app_context():
                        ak,jwk,net,cli = _make_engine(domain)
                    ab = Authorization.from_json(cli._post_as_get(state["authorization_uri"]).json())
                    if ab.status.name!="valid":
                        cbd = ChallengeBody.from_json(cli._post_as_get(state["challenge_uri"]).json())
                        cli.answer_challenge(cbd,DNS01Response())
                        for _ in range(100):
                            time.sleep(3)
                            ab=Authorization.from_json(cli._post_as_get(state["authorization_uri"]).json())
                            if ab.status.name=="valid": break
                            elif ab.status.name=="invalid":
                                errs=[f"{c.error.typ}:{c.error.detail}" for c in ab.challenges if c.error]
                                with app.app_context():
                                    state["status"]="invalid";state["error"]="; ".join(errs) or "验证失败"
                                    sf.write_text(json.dumps(state,indent=2)); return
                        else: state["status"]="timeout"; sf.write_text(json.dumps(state,indent=2)); return
                    dk=_load_or_create_domain_key(sdir); dk_pem=dk.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())
                    csr_pem=make_csr(dk_pem,[domain])
                    ob=Order.from_json(cli._post_as_get(state["order_uri"]).json())
                    or_=OrderResource(body=ob,uri=state["order_uri"],csr_pem=csr_pem,
                                    authorizations=[AuthorizationResource(body=ab,uri=state["authorization_uri"])])
                    deadline=datetime.utcnow()+timedelta(seconds=300)
                    try: or_=cli.finalize_order(or_,deadline)
                    except: pass
                    od=cli._post_as_get(state["order_uri"]).json()
                    cu=od.get("certificate","")
                    if cu: cert_pem=requests.get(cu).text; (sdir/"fullchain.pem").write_text(cert_pem); state["certificate"]=cert_pem
                    state["status"]="completed"; sf.write_text(json.dumps(state,indent=2))
                    with app.app_context():
                        db=get_db(); _ensure_cert_record(db,state["user_id"],domain,state)
                except Exception as e:
                    with app.app_context():
                        state["status"]="error";state["error"]=str(e); sf.write_text(json.dumps(state,indent=2))
                finally: _running.pop(domain,None)
            return _verify_bg
        t=threading.Thread(target=_mk_verify(domain, state),daemon=True)
        _running[domain]=t; t.start()
        results.append({"domain":domain,"status":"verifying"})
    if len(results) == 1:
        r = results[0]
        return jsonify({"status":r["status"],"domain":r["domain"],"certificate":r.get("certificate",""),"private_key":r.get("private_key",""),"error":r.get("error","")})
    return jsonify({"results":results})


@app.route("/api/acme/status", methods=["POST"])
@require_auth
def api_acme_status():
    data=request.get_json(); domain=data.get("domain","").strip()
    sdir=STATE_ROOT/domain; sf=sdir/"state.json"
    if not sf.exists(): return jsonify({"status":"not_found"})
    state=json.loads(sf.read_text())
    if state.get("status")=="completed":
        ct=(sdir/"fullchain.pem").read_text() if (sdir/"fullchain.pem").exists() else state.get("certificate","")
        pk=(sdir/"domain_key.pem").read_text() if (sdir/"domain_key.pem").exists() else ""
        db=get_db(); _ensure_cert_record(db,g.user_id,domain,state)
        return jsonify({"status":"completed","domain":domain,"certificate":ct,"private_key":pk})
    return jsonify({"status":state.get("status","unknown"),"error":state.get("error","")})


@app.route("/api/acme/email", methods=["POST"])
@require_auth
def api_acme_email():
    data=request.get_json(); domain=data.get("domain","").strip(); email=data.get("email","").strip()
    if not domain or not email: return jsonify({"error":"缺少参数"}), 400
    sdir=STATE_ROOT/domain; cp=sdir/"fullchain.pem"; kp=sdir/"domain_key.pem"
    if not cp.exists(): return jsonify({"error":"证书文件不存在"}), 404
    if not SMTP_HOST: return jsonify({"error":"SMTP未配置"}), 500
    try:
        msg=MIMEMultipart()
        msg["Subject"]=f"SSL证书 - {domain}"; msg["From"]=SMTP_FROM; msg["To"]=email
        msg.attach(MIMEText(f"您好，\n\n{domain} 的 SSL证书和私钥见附件。\n\n证书有效期：90天\n","plain","utf-8"))
        for p,rn in [(cp,f"{domain}_cert.pem"),(kp,f"{domain}_key.pem")]:
            if p.exists():
                part=MIMEBase("application","x-pem-file"); part.set_payload(p.read_text())
                encoders.encode_base64(part); part.add_header("Content-Disposition",f"attachment; filename={rn}")
                msg.attach(part)
        with smtplib.SMTP_SSL(SMTP_HOST,SMTP_PORT,timeout=10) as s:
            s.login(SMTP_USER,SMTP_PASS); s.sendmail(SMTP_FROM,[email],msg.as_string())
        return jsonify({"status":"sent","message":f"已发送到 {email}"})
    except Exception as e: return jsonify({"error":f"发送失败: {e}"}), 500


# ════════════════════════ 页面路由 ════════════════════════

@app.route("/api/acme/download/<domain>/<ft>")
@require_auth
def api_acme_download(domain, ft):
    """从 state 路径下载证书（给签发流程用）"""
    sdir = STATE_ROOT / domain
    sf = sdir / "state.json"
    if not sf.exists():
        return jsonify({"error":"状态文件不存在"}), 404
    state = json.loads(sf.read_text())
    if ft == "cert":
        t = state.get("certificate","")
        if not t:
            fp = sdir / "fullchain.pem"
            if fp.exists(): t = fp.read_text()
        if not t: return jsonify({"error":"证书为空"}), 404
        return Response(t, mimetype="application/x-pem-file",
                       headers={"Content-Disposition":f"attachment; filename={domain}_cert.pem"})
    elif ft == "key":
        kp = sdir / "domain_key.pem"
        if not kp.exists(): return jsonify({"error":"私钥不存在"}), 404
        return send_file(str(kp), mimetype="application/x-pem-file",
                       as_attachment=True, download_name=f"{domain}_key.pem")
    elif ft == "all":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as z:
            ct = state.get("certificate","")
            if ct: z.writestr(f"{domain}_cert.pem",ct)
            else:
                fp = sdir / "fullchain.pem"
                if fp.exists(): z.write(str(fp),f"{domain}_cert.pem")
            kp = sdir / "domain_key.pem"
            if kp.exists(): z.write(str(kp),f"{domain}_key.pem")
        buf.seek(0)
        return send_file(buf, mimetype="application/zip",
                       as_attachment=True, download_name=f"{domain}_ssl.zip")
    return jsonify({"error":"未知文件类型"}), 400


@app.route("/")
def index():
    return render_template("portal.html")


# ════════════════════════ 主入口 ════════════════════════

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 10501
    os.makedirs("templates", exist_ok=True)
    init_db()
    seed_admin()
    backfill_expires()
    print(f"[✓] 管理门户启动: http://0.0.0.0:{port}")
    print(f"    SMTP: {'已配置' if SMTP_HOST else '未配置（开发模式）'}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
