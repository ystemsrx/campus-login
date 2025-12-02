# -*- coding: utf-8 -*-
import re
import random
import base64
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

USERNAME = "your_id_here"
PASSWORD = "your_password_here"

LOGIN_URL = (
    "https://idas.uestc.edu.cn/authserver/login"
    "?service=https%3A%2F%2Feportal.uestc.edu.cn%2Flogin%3Fservice%3D"
    "https%3A%2F%2Feportal.uestc.edu.cn%2Fnew%2Findex.html%3Fbrowser%3Dno"
)

def rand_str(n: int) -> str:
    """生成随机前缀 / IV"""
    chars = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
    return "".join(random.choice(chars) for _ in range(n))


def aes_pwd(pwd: str, salt: str) -> str:
    """AES-CBC-PKCS7 加密密码"""
    salt = salt.strip()
    prefix = rand_str(64)
    iv_str = rand_str(16)

    pt = (prefix + pwd).encode("utf-8")
    key = salt.encode("utf-8")
    iv = iv_str.encode("utf-8")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(pt, AES.block_size))
    return base64.b64encode(ct).decode("utf-8")


def get_val(html: str, field_id: str, default: str = "") -> str:
    """从 HTML 中取 input 的 value"""
    p_id = rf'id="{re.escape(field_id)}"[^>]*value="([^"]*)"'
    m = re.search(p_id, html)
    if m:
        return m.group(1)

    p_name = rf'name="{re.escape(field_id)}"[^>]*value="([^"]*)"'
    m = re.search(p_name, html)
    if m:
        return m.group(1)

    return default


def get_meta(session: requests.Session):
    """GET 登录页并解析关键字段"""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/142.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
    }

    r = session.get(LOGIN_URL, headers=headers, timeout=10)

    html = r.text
    salt = get_val(html, "pwdEncryptSalt")
    execution = get_val(html, "execution")
    lt = get_val(html, "lt", "")

    return {
        "salt": salt,
        "execution": execution,
        "lt": lt,
    }


def login():
    with requests.Session() as session:
        meta = get_meta(session)

        if not meta["salt"] or not meta["execution"]:
            print("[!] 解析不到 pwdEncryptSalt / execution")
            return

        enc_pwd = aes_pwd(PASSWORD, meta["salt"])

        data = {
            "username": USERNAME,
            "password": enc_pwd,
            "captcha": "",
            "_eventId": "submit",
            "cllt": "userNameLogin",
            "dllt": "generalLogin",
            "lt": meta["lt"],
            "execution": meta["execution"],
        }

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/142.0.0.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8,"
                "application/signed-exchange;v=b3;q=0.7"
            ),
            "Origin": "https://idas.uestc.edu.cn",
            "Referer": LOGIN_URL,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        r = session.post(
            LOGIN_URL,
            headers=headers,
            data=data,
            allow_redirects=False,
            timeout=10,
        )

        print("[*] status:", r.status_code)
        loc = r.headers.get("Location")

        if r.status_code in (301, 302) and loc:
            print("[+] 登录成功 ->", loc)
        else:
            print("[!] 看起来登录失败了")


if __name__ == "__main__":
    login()
