# -*- coding: utf-8 -*-
import re
import textwrap
import base64

import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


LOGIN_PAGE_URL = (
    "https://library.nudt.edu.cn/sso/login"
    "?wfwfid=182&refer=https://library.nudt.edu.cn/"
)
LOGIN_URL = "https://library.nudt.edu.cn/sso/login"

USERNAME = "your_id_here"
PASSWORD = "your_password_here"


def get_pubkey_pem(session: requests.Session) -> str:
    """GET 登录页并提取 RSA 公钥（PEM）"""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/142.0.0.0 Safari/537.36"
        )
    }
    resp = session.get(LOGIN_PAGE_URL, headers=headers, timeout=15)
    resp.raise_for_status()
    html = resp.text

    m = re.search(r'pubKey:"([^"]+)"', html)
    if not m:
        raise RuntimeError("无法在登录页中找到 pubKey")

    pubkey_b64 = m.group(1).replace("\\/", "/")
    pem_lines = textwrap.wrap(pubkey_b64, 64)
    pubkey_pem = (
        "-----BEGIN PUBLIC KEY-----\n"
        + "\n".join(pem_lines)
        + "\n-----END PUBLIC KEY-----\n"
    )
    return pubkey_pem


def encrypt_rsa(plaintext: str, pubkey_pem: str) -> str:
    """使用 RSA-PKCS1v1.5 加密并返回 Base64"""
    key = RSA.import_key(pubkey_pem)
    cipher = PKCS1_v1_5.new(key)
    ct = cipher.encrypt(plaintext.encode("utf-8"))
    return base64.b64encode(ct).decode("ascii")


def login():
    with requests.Session() as session:
        pubkey_pem = get_pubkey_pem(session)

        enc_account = encrypt_rsa(USERNAME, pubkey_pem)
        enc_password = encrypt_rsa(PASSWORD, pubkey_pem)

        data = {
            "account": enc_account,
            "password": enc_password,
            "wfwfid": "182",
        }

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/142.0.0.0 Safari/537.36"
            ),
            "Referer": "https://library.nudt.edu.cn/",
            "Origin": "https://library.nudt.edu.cn",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        }

        resp = session.post(LOGIN_URL, data=data, headers=headers, timeout=15)
        print("[*] status:", resp.status_code)

        try:
            j = resp.json()
            ok = j.get("success")
            code = j.get("code")
            msg = j.get("message")
            if ok:
                print("[+] 登录成功")
            else:
                print("[!] 看起来登录失败了:", code, msg)
        except Exception:
            print("[!] 无法解析 JSON 响应")
            print(resp.text[:300])


if __name__ == "__main__":
    login()
