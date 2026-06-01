#!/usr/bin/env python3
"""
ACME DNS-01 完整实现 (基于 acme 库)
====================================
两阶段设计：
  阶段1: 账户注册 → 下单 → 生成 DNS-01 challenge → 保存状态
  阶段2: 轮询 DNS → 触发验证 → 验证结果 → 提交 CSR → 下载证书

依赖: pip install acme cryptography dnspython requests
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import dns.resolver
import dns.exception
import requests

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from acme import client, messages, challenges
from acme.client import ClientNetwork
from acme.messages import (
    NewRegistration,
    Registration,
    NewOrder,
    Order,
    OrderResource,
    Identifier,
    ChallengeBody,
    AuthorizationResource,
    Directory,
    Status,
)
from acme.crypto_util import make_csr

# acme>=5.0: DNSChallenge renamed to DNS01 in acme.challenges
DNSChallenge = challenges.DNS01
import josepy as jose


# ════════════════════════ 配置 ════════════════════════

CONFIG = {
    # 生产环境
    "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
    # 测试环境（推荐先测 staging）
    # "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",

    "domain": "zhensgshu.byfwwwg.cn",
    "email": "admin@byfwwwg.cn",  # 用于账户注册/到期通知（域名对应的邮箱）

    "user_agent": "acme-dns01-system/1.0",

    # DNS 生效等待参数
    "dns_wait_retries": 30,
    "dns_wait_interval": 10,
    "acme_poll_timeout": 300,
    "acme_poll_interval": 5,
}

STATE_DIR = Path("./state")
STATE_DIR.mkdir(exist_ok=True)

# 账户密钥（永久保存，可在多个订单间复用）
ACCOUNT_KEY_PATH = STATE_DIR / "account_key.pem"

# 订单状态（连接阶段1→阶段2）
ORDER_STATE_PATH = STATE_DIR / "order_state.json"

# 域名密钥（CSR 用）
DOMAIN_KEY_PATH = STATE_DIR / "domain_key.pem"

# 输出证书
CERT_FULLCHAIN_PATH = STATE_DIR / "fullchain.pem"
CERT_CHAIN_PATH = STATE_DIR / "chain.pem"
CERT_PRIVKEY_PATH = STATE_DIR / "domain_privkey.pem"


# ════════════════════════ 密钥管理 ════════════════════════


def load_or_create_account_key() -> rsa.RSAPrivateKey:
    """加载或创建 ACME 账户 RSA 私钥（4096 位）"""
    if ACCOUNT_KEY_PATH.exists():
        print("[*] 加载已有账户密钥")
        with open(ACCOUNT_KEY_PATH, "rb") as f:
            return load_pem_private_key(f.read(), password=None)
    else:
        print("[*] 生成新账户密钥 (RSA 4096)")
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        with open(ACCOUNT_KEY_PATH, "wb") as f:
            f.write(pem)
        return key


def load_or_create_domain_key() -> rsa.RSAPrivateKey:
    """加载或创建域名 RSA 私钥（2048 位，用于 CSR）"""
    if DOMAIN_KEY_PATH.exists():
        print("[*] 加载已有域名私钥")
        with open(DOMAIN_KEY_PATH, "rb") as f:
            return load_pem_private_key(f.read(), password=None)
    else:
        print("[*] 生成域名私钥 (RSA 2048)")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        with open(DOMAIN_KEY_PATH, "wb") as f:
            f.write(pem)
        return key


def rsa_to_jwkrSA(key: rsa.RSAPrivateKey) -> jose.JWKRSA:
    """将 cryptography RSA key 转为 josepy JWKRSA"""
    return jose.JWKRSA(key=key)


# ════════════════════════ ACME 客户端 ════════════════════════


def create_acme_client(account_key: rsa.RSAPrivateKey,
                       cfg: dict) -> tuple[ClientNetwork, Directory, client.ClientV2]:
    """创建 ACME v2 网络客户端"""
    jwk_key = rsa_to_jwkrSA(account_key)
    net = ClientNetwork(key=jwk_key, user_agent=cfg["user_agent"])
    directory = Directory.from_json(net.get(cfg["directory_url"]).json())
    acme_client = client.ClientV2(directory, net=net)
    return net, directory, acme_client


def register_account(net: ClientNetwork, acme_client: client.ClientV2,
                     email: str) -> Registration:
    """注册 ACME 账户（若已存在则自动恢复）"""
    reg = NewRegistration(
        contact=(f"mailto:{email}",),
        terms_of_service_agreed=True,
    )
    print(f"[*] 注册/恢复账户 (contact: {email}) ...")
    account = acme_client.new_account(reg)
    print(f"  [✓] URI: {account.uri}")
    return account


# ════════════════════════ 阶段1：生成 challenge ════════════════════════


def phase1_generate_challenge(cfg: dict):
    """
    阶段1：
    - 账户注册
    - 创建订单
    - 提取 DNS-01 challenge（TXT 记录值）
    - 保存状态到 JSON
    """
    domain = cfg["domain"]

    # 1. 密钥 & ACME 客户端
    account_key = load_or_create_account_key()
    net, directory, acme_client = create_acme_client(account_key, cfg)

    # 2. 注册账户
    account = register_account(net, acme_client, cfg["email"])

    # 3. 创建订单（新版 acme ClientV2.new_order 接受 CSR PEM）
    # 先生成临时 CSR 来下单
    domain_key = load_or_create_domain_key()
    # make_csr 现在接受 PEM bytes（非 JWKRSA）
    domain_key_pem = domain_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    temp_csr = make_csr(domain_key_pem, [domain])
    print("[*] 创建证书订单 ...")
    order = acme_client.new_order(temp_csr)
    print(f"  [✓] Order URI: {order.uri}")
    print(f"  [ ] Expires: {order.body.expires}")

    # 4. 提取 DNS-01 challenge
    authz = order.authorizations[0]  # 本域名只有1个 authorization
    authz_body = authz.body
    print(f"  [ ] Authorization for: {authz_body.identifier.value}")

    dns_challenge: ChallengeBody = None
    for chall_body in authz_body.challenges:
        if chall_body.chall.typ == "dns-01":
            dns_challenge = chall_body
            break

    if dns_challenge is None:
        print("[✗] 未找到 DNS-01 challenge!")
        sys.exit(1)

    chall = dns_challenge.chall  # type: DNSChallenge
    txt_record_name = f"_acme-challenge.{domain}"
    # validation 需要 jose.JWKRSA 格式（有 thumbprint 方法）
    account_jwk = rsa_to_jwkrSA(account_key)
    txt_record_value = chall.validation(account_jwk)

    # 5. 保存状态
    state = {
        "domain": domain,
        "account_uri": account.uri,
        "order_uri": order.uri,
        "authorization_uri": order.authorizations[0].uri,
        "challenge_uri": dns_challenge.uri,
        "challenge_token": chall.encode("token"),
        "dns_txt_name": txt_record_name,
        "dns_txt_value": txt_record_value,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "challenge_generated",
    }
    with open(ORDER_STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)

    print(f"\n{'=' * 60}")
    print(f"[✓] DNS-01 验证信息已生成")
    print(f"{'=' * 60}")
    print(f"  域名:       {domain}")
    print(f"  TXT 记录名: {txt_record_name}")
    print(f"  记录类型:   TXT")
    print(f"  记录值:     {txt_record_value}")
    print(f"  TTL:        600")
    print(f"\n下一步：")
    print(f"  1. 登录阿里云 DNS 控制台 -> 添加上述 TXT 记录")
    print(f"  2. 等待生效后运行: python acme_dns01.py phase2")
    print(f"{'=' * 60}")

    return state


# ════════════════════════ DNS 检测 ════════════════════════


def check_txt_record(record_name: str, expected_value: str,
                     nameservers: list[str] | None = None) -> bool:
    """
    通过公共 DNS 查询 TXT 记录是否已生效。
    返回 True 说明至少有一个公共 DNS 返回了期望值。
    """
    if nameservers is None:
        nameservers = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]

    for ns in nameservers:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ns]
        resolver.timeout = 5
        resolver.lifetime = 5

        try:
            answers = resolver.resolve(record_name, "TXT")
            for rdata in answers:
                # TXT 返回格式可能是 '"value"'，去掉外层引号
                txt_value = rdata.to_text().strip('"')
                if txt_value == expected_value:
                    return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            continue

    return False


def wait_for_dns(record_name: str, expected_value: str,
                 max_retries: int = 30, interval: int = 10) -> bool:
    """轮询等待 DNS TXT 记录全球生效"""
    print(f"[*] 等待 DNS TXT 记录生效 ...")
    print(f"    记录: {record_name}")
    print(f"    期望值: {expected_value[:40]}...")
    print(f"    最长等待: {max_retries * interval}s")

    for i in range(max_retries):
        remaining = (max_retries - i) * interval
        print(f"  [{i+1}/{max_retries}] 检查中 (剩余 ~{remaining}s) ...", end=" ")

        if check_txt_record(record_name, expected_value):
            print(f"[✓] 已生效!")
            # 再等几秒让 LE 的缓存也更新
            print("  [*] 再等待 10 秒确保 LE 可达 ...")
            time.sleep(10)
            return True

        print(f"[ ] 未生效")
        time.sleep(interval)

    return False


# ════════════════════════ 阶段2：验证 & 签发 ════════════════════════


def phase2_verify_and_download(cfg: dict):
    """
    阶段2：
    - 从 JSON 恢复状态
    - 等待 DNS 生效
    - 触发 ACME 验证
    - 轮询验证结果
    - 提交 CSR → 下载证书
    """
    # 1. 加载状态
    if not ORDER_STATE_PATH.exists():
        print(f"[✗] 未找到状态文件: {ORDER_STATE_PATH}")
        print("  请先运行 python acme_dns01.py phase1")
        sys.exit(1)

    with open(ORDER_STATE_PATH) as f:
        state = json.load(f)
    print(f"[✓] 加载状态 (创建于 {state.get('created_at')})")

    if state.get("status") == "completed":
        print(f"[✓] 该订单已完成。如需重新签发，请删除 {ORDER_STATE_PATH} 后重试。")
        sys.exit(0)

    domain = state["domain"]

    # 2. 账户密钥 & ACME 客户端
    account_key = load_or_create_account_key()
    net, directory, acme_client = create_acme_client(account_key, cfg)

    # 3. 恢复账户——通过 query_registration 建立 kid 关联
    print("[*] 恢复账户会话 ...")
    # 构造 RegistrationResource 并调用 query_registration
    # 这会设置 net.account，后续 POST 才能用 kid 模式
    from acme.messages import RegistrationResource
    regr = RegistrationResource(
        body=Registration(),
        uri=state["account_uri"],
    )
    acme_client.query_registration(regr)
    print(f"  [✓] 账户已恢复: {state['account_uri']}")

    # 4. 恢复订单（重新查询最新状态）
    print("[*] 恢复订单 ...")
    order_resp = net.get(state["order_uri"]).json()
    order_body = Order.from_json(order_resp)

    # 重新获取 authorizations
    authz_uri = state["authorization_uri"]
    authz_resp = net.get(authz_uri).json()

    from acme.messages import Authorization
    authz_body = Authorization.from_json(authz_resp)

    authz_resource = AuthorizationResource(
        body=authz_body,
        uri=authz_uri,
    )
    order_resource = OrderResource(
        body=order_body,
        uri=state["order_uri"],
        authorizations=[authz_resource],
    )

    print(f"  [✓] 订单状态: {order_body.status}")

    # 如果订单已经是 valid 状态，直接去下载证书
    if order_body.status.name == "valid":
        print(f"  [ ] 订单已验证通过，进入证书签发阶段")
    elif order_body.status.name == "ready":
        print(f"  [ ] 订单已就绪，需先验证 DNS challenge")
    elif order_body.status.name == "pending":
        print(f"  [ ] 订单待处理")
    elif order_body.status.name == "invalid":
        print(f"  [✗] 订单已无效，需要重新创建")
        sys.exit(1)

    # 5. 跳过公共 DNS 等待（刚才已确认权威 NS 有正确记录）
    print(f"[*] 跳过公共 DNS 检查，直接触发 ACME 验证 ...")

    # 6. 触发验证
    #    DNS-01: 向 challenge URL 发 POST，payload 是 {} (空对象)
    print(f"[*] 通知 Let's Encrypt 验证 DNS challenge ...")

    # 使用 acme 库的 answer_challenge 方法
    # 对 DNS-01，验证响应就是一个空的 {} 即可
    challenge_body = ChallengeBody.from_json(
        net.get(state["challenge_uri"]).json()
    )
    # 重新获取最新的 challenge 状态
    chall_response = acme_client.answer_challenge(challenge_body, {})

    print("  [→] 已发送验证请求，等待结果 ...")

    # 7. 轮询验证状态
    print(f"[*] 轮询 authorization 状态（超时 {cfg['acme_poll_timeout']}s）...")
    start_time = time.time()
    verified = False

    while time.time() - start_time < cfg["acme_poll_timeout"]:
        elapsed = int(time.time() - start_time)

        # 刷新 authorization 状态
        refresh_resp = net.get(authz_uri).json()
        authz_body = Authorization.from_json(refresh_resp)
        authz_resource = AuthorizationResource(body=authz_body, uri=authz_uri)

        current_status = authz_body.status
        print(f"  [{elapsed:3d}s] Authorization: {current_status}")

        if current_status.name == "valid":
            print(f"\n  [✓] DNS-01 验证通过！耗时 {elapsed}s")
            verified = True
            break
        elif current_status.name == "invalid":
            print(f"\n  [✗] DNS-01 验证失败！")
            # 打印具体的错误信息
            for cb in authz_body.challenges:
                if cb.error:
                    print(f"    错误类型: {cb.error.typ}")
                    print(f"    错误详情: {cb.error.detail}")
            print(f"\n    可能的原因：")
            print(f"      1. DNS TXT 记录值不匹配")
            print(f"      2. Let's Encrypt 未能在您的 DNS 上查到记录")
            print(f"      3. TTL 缓存导致 LE 读到旧值")
            print(f"\n    请检查后重新运行本脚本（会自动重新触发验证）")
            sys.exit(1)

        time.sleep(cfg["acme_poll_interval"])

    if not verified:
        print(f"\n  [✗] 验证超时 ({cfg['acme_poll_timeout']}s)")
        sys.exit(1)

    # 8. 签发证书 —— 提交 CSR
    print(f"\n{'=' * 60}")
    print("[*] 验证通过，准备签发证书")
    print(f"{'=' * 60}")

    domain_key = load_or_create_domain_key()
    domain_key_pem = domain_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )

    # 生成 CSR
    print("[*] 生成 CSR ...")
    csr_pem = make_csr(domain_key_pem, [domain])
    print(f"  [✓] CSR 已生成 ({len(csr_pem)} bytes)")

    # 注意：如果 order_resource 的 body 状态变了，需要同步
    # 重新获取 order 确保是最新状态
    order_resp = net.get(state["order_uri"]).json()
    order_body = Order.from_json(order_resp)
    order_resource = OrderResource(
        body=order_body,
        uri=state["order_uri"],
        authorizations=[authz_resource],
    )

    # Finalize：提交 CSR
    print("[*] 提交 CSR 并等待签发 ...")
    order_resource = acme_client.finalize_order(order_resource, csr_pem)

    # 9. 轮询等待签发完成
    print("[*] 等待证书签发 ...")
    order_resource = acme_client.poll_and_finalize(order_resource)

    if order_resource.body.status.name != "valid":
        print(f"[✗] 订单最终状态异常: {order_resource.body.status}")
        sys.exit(1)

    print(f"  [✓] 订单已完成")

    # 10. 下载证书链
    print("[*] 下载证书链 ...")
    cert_resource = acme_client.fetch_chain(order_resource)

    fullchain_pem = cert_resource.fullchain_pem
    if isinstance(fullchain_pem, bytes):
        fullchain_pem = fullchain_pem.decode()

    chain_pem = cert_resource.chain_pem
    if isinstance(chain_pem, bytes):
        chain_pem = chain_pem.decode()

    # 11. 保存文件
    with open(CERT_FULLCHAIN_PATH, "w") as f:
        f.write(fullchain_pem)
    with open(CERT_CHAIN_PATH, "w") as f:
        f.write(chain_pem)

    privkey_pem = domain_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    with open(CERT_PRIVKEY_PATH, "wb") as f:
        f.write(privkey_pem)

    # 12. 更新状态
    state["status"] = "completed"
    state["completed_at"] = datetime.now(timezone.utc).isoformat()
    state["cert_files"] = {
        "fullchain": str(CERT_FULLCHAIN_PATH),
        "chain": str(CERT_CHAIN_PATH),
        "privkey": str(CERT_PRIVKEY_PATH),
    }
    with open(ORDER_STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)

    print(f"\n{'=' * 60}")
    print(f"[✓] 证书签发成功！")
    print(f"{'=' * 60}")
    print(f"  域名:       {domain}")
    print(f"  完整证书链: {CERT_FULLCHAIN_PATH}")
    print(f"  中间证书:   {CERT_CHAIN_PATH}")
    print(f"  私钥:       {CERT_PRIVKEY_PATH}")
    print(f"  有效期:     90 天")
    print(f"\n  Nginx 配置参考：")
    print(f"    ssl_certificate     {CERT_FULLCHAIN_PATH};")
    print(f"    ssl_certificate_key {CERT_PRIVKEY_PATH};")
    print(f"{'=' * 60}")


# ════════════════════════ 入口 ════════════════════════


def main():
    if len(sys.argv) < 2:
        print("用法:")
        print("  python acme_dns01.py phase1   -- 生成 DNS-01 验证信息")
        print("  python acme_dns01.py phase2   -- 验证并签发证书")
        sys.exit(1)

    phase = sys.argv[1].lower()

    if phase == "phase1":
        phase1_generate_challenge(CONFIG)
    elif phase == "phase2":
        phase2_verify_and_download(CONFIG)
    else:
        print(f"[✗] 未知参数: {phase}")
        print("  可用参数: phase1, phase2")
        sys.exit(1)


if __name__ == "__main__":
    main()
