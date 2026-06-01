#!/usr/bin/env python3
"""阶段2快捷版：跳过 DNS 公共检查，直连权威 NS 验证后签发"""
import json, sys, time
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PrivateFormat, NoEncryption
from acme import client, messages
from acme.client import ClientNetwork
from acme.messages import (Registration, Order, OrderResource, ChallengeBody, AuthorizationResource, Directory)
from acme.challenges import DNS01
from acme.crypto_util import make_csr
import josepy as jose

STATE = Path("state")
with open(STATE / "order_state.json") as f:
    s = json.load(f)

# 密钥 & 网络
key = load_pem_private_key((STATE / "account_key.pem").read_bytes(), password=None)
jwk = jose.JWKRSA(key=key)
net = ClientNetwork(key=jwk, user_agent="acme-dns01/1.0")
directory = Directory.from_json(net.get("https://acme-v02.api.letsencrypt.org/directory").json())

# 恢复账户 & 订单（必须先绑定 kid）
print("[*] 恢复账户 & 订单...", flush=True)
acme_cli = client.ClientV2(directory, net=net)
# 用 only_return_existing=True 查询已有账户，建立 kid 关联
try:
    acme_cli.new_account(Registration(terms_of_service_agreed=True, only_return_existing=True))
    print("  账户已恢复", flush=True)
except Exception as e:
    print(f"  恢复账户异常: {e}，尝试 POST-as-GET", flush=True)
    net.post(s["account_uri"], Registration())

order_body = Order.from_json(net.get(s["order_uri"]).json())
authz_body = messages.Authorization.from_json(net.get(s["authorization_uri"]).json())
print(f"  Authz状态: {authz_body.status}", flush=True)

# 找到 dns-01 challenge
cb = None
for c in authz_body.challenges:
    if c.chall.typ == "dns-01":
        cb = c
        break

# 触发验证
print("[*] 触发验证...", flush=True)
# DNS-01: answer_challenge 传入 challenge body + {} 即可
chall_response = acme_cli.answer_challenge(cb, {})
print(f"  → 已通知 LE 验证", flush=True)

# 轮询
print("[*] 轮询状态...", flush=True)
start = time.time()
verified = False
while time.time() - start < 300:
    elapsed = int(time.time() - start)
    resp_data = net.get(s["authorization_uri"]).json()
    az = messages.Authorization.from_json(resp_data)
    print(f"  [{elapsed:3d}s] {az.status}", flush=True)
    if az.status.name == "valid":
        verified = True
        break
    elif az.status.name == "invalid":
        for c in az.challenges:
            if c.error:
                print(f"  错误: {c.error.typ}: {c.error.detail}", flush=True)
        sys.exit(1)
    time.sleep(3)

if not verified:
    print("[✗] 超时", flush=True)
    sys.exit(1)

# 签发证书
print("[*] 签发证书...", flush=True)
# 加载域名密钥
if not (STATE / "domain_key.pem").exists():
    from cryptography.hazmat.primitives.asymmetric import rsa
    dk = rsa.generate_private_key(65537, 2048)
    pem = dk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    (STATE / "domain_key.pem").write_bytes(pem)
else:
    dk = load_pem_private_key((STATE / "domain_key.pem").read_bytes(), password=None)
    
dk_pem = dk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
csr = make_csr(dk_pem, [s["domain"]])

order_body = Order.from_json(net.get(s["order_uri"]).json())
order_resource = OrderResource(body=order_body, uri=s["order_uri"], authorizations=[
    AuthorizationResource(body=az, uri=s["authorization_uri"])
])
order_resource = acme_cli.finalize_order(order_resource, csr)
order_resource = acme_cli.poll_and_finalize(order_resource)

if order_resource.body.status.name != "valid":
    print(f"[✗] 签发失败: {order_resource.body.status}", flush=True)
    sys.exit(1)

# 下载
cert_resource = acme_cli.fetch_chain(order_resource)
fullchain = cert_resource.fullchain_pem.decode() if isinstance(cert_resource.fullchain_pem, bytes) else cert_resource.fullchain_pem
chain = cert_resource.chain_pem.decode() if isinstance(cert_resource.chain_pem, bytes) else cert_resource.chain_pem

(STATE / "fullchain.pem").write_text(fullchain)
(STATE / "chain.pem").write_text(chain)

# 保存状态
s["status"] = "completed"
s["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
with open(STATE / "order_state.json", "w") as f:
    json.dump(s, f, indent=2)

print(f"[✓] 完成！")
print(f"\n证书: state/fullchain.pem")
print(f"私钥: state/domain_privkey.pem")
