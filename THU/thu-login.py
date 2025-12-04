# -*- coding: utf-8 -*-
import random
import requests
from bs4 import BeautifulSoup
from gmssl import sm2


USERNAME = "your_id_here"
PASSWORD = "your_password_here"

LOGIN_PAGE_URL = (
    "https://id.tsinghua.edu.cn/do/off/ui/auth/login/form/"
    "f2841607a1c6b880847ee635cc5046f0/1"
)
LOGIN_POST_URL = "https://id.tsinghua.edu.cn/do/off/ui/auth/login/check"


def random_hex32():
    """生成 32 hex（16 bytes），作为 fingerPrint。"""
    return "".join(random.choice("0123456789abcdef") for _ in range(32))


def parse_public_key(html):
    soup = BeautifulSoup(html, "lxml")
    div = soup.find(id="sm2publicKey")
    pk = div.get_text(strip=True)
    if not pk.startswith("04"):
        raise RuntimeError("未找到 SM2 公钥")
    return pk


def sm2_encrypt(password, pubkey_hex):
    crypt = sm2.CryptSM2(public_key=pubkey_hex, private_key="", mode=1)
    cipher = crypt.encrypt(password.encode())
    return "04" + cipher.hex()


def is_fail(html):
    if "您的用户名或密码不正确" in html:
        return True
    if 'id="theform"' in html:
        return True
    return False


def main():
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/142"
    })

    # 获取公钥
    r = session.get(LOGIN_PAGE_URL, timeout=10)
    pubkey = parse_public_key(r.text)

    # SM2 加密密码
    enc_pass = sm2_encrypt(PASSWORD, pubkey)

    # 指纹
    fp = random_hex32()

    data = {
        "i_user": USERNAME,
        "i_pass": enc_pass,
        "fingerPrint": fp,
        "fingerGenPrint": "",
        "fingerGenPrint3": "",
        "i_captcha": "",
    }

    r2 = session.post(LOGIN_POST_URL, data=data, timeout=10, allow_redirects=True)
    print("[*] status:", r2.status_code)

    if is_fail(r2.text):
        print("[-] 看起来登录失败了")
    else:
        print("[+] 登录成功")


if __name__ == "__main__":
    main()
