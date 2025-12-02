# -*- coding: utf-8 -*-
import re
import base64
import requests
from urllib.parse import unquote
from urllib3.exceptions import InsecureRequestWarning

from encrypt import strEnc_js

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

ACCOUNT = "your_id_here"
PASSWORD = "your_password_here"

LOGIN_PAGE = (
    "https://idm.swu.edu.cn/am/UI/Login"
    "?realm=%2F"
    "&service=initService"
    "&goto=http%3A%2F%2Fidm.swu.edu.cn%2Fam%2Foauth2%2Fauthorize%3Fservice%3DinitService%26response_type%3Dcode%26client_id%3D7c1zokoljl9bbiho6yuo%26scope%3Duid%2Bcn%2BuserIdCode%26redirect_uri%3Dhttps%253A%252F%252Fuaaap.swu.edu.cn%252Fcas%252Flogin%253Fservice%253Dhttps%25253a%25252f%25252fjw.swu.edu.cn%25252fsso%25252fzllogin%2526federalEnable%253Dtrue%26decision%3DAllow"
)

POST_URL = "https://idm.swu.edu.cn/am/UI/Login"
SUN_QUERY_PARAMS = "realm=/&service=initService&gx_charset=UTF-8"

HEADERS = {
    "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Accept-Language": "zh-CN,zh;q=0.9",
}


def login():
    with requests.Session() as sess:

        # 1) GET 登录页
        r0 = sess.get(LOGIN_PAGE, headers=HEADERS, verify=False)
        html = r0.text

        # 2) 提取 random/codeRandom 作为加密 key
        m = re.search(r'(?:id|name)="(?:random|codeRandom)".*?value="([^"]+)"', html)
        if not m:
            print("[*] status: N/A")
            print("[*] final URL: N/A")
            print("[!] 看起来登录失败了（没找到加密 key）")
            return

        key = m.group(1)

        # 3) 提取 goto
        goto_match = re.search(r"goto=([^&\"]+)", r0.url)
        goto_raw = unquote(goto_match.group(1)) if goto_match else ""
        goto_b64 = base64.b64encode(goto_raw.encode()).decode()

        # base64 的 SunQueryParamsString
        sun_b64 = base64.b64encode(SUN_QUERY_PARAMS.encode()).decode()

        # 4) 用 strEnc_js 加密账号密码
        enc_user = strEnc_js(ACCOUNT, key, "", "")
        enc_pwd  = strEnc_js(PASSWORD, key, "", "")

        # 5) 构造 POST Form
        data = {
            "IDToken1": enc_user,
            "IDToken2": enc_pwd,
            "IDToken3": "",
            "goto": goto_b64,
            "gotoOnFail": "",
            "SunQueryParamsString": sun_b64,
            "encoded": "true",
            "gx_charset": "UTF-8",
        }

        headers2 = dict(HEADERS)
        headers2["Referer"] = r0.url
        headers2["Content-Type"] = "application/x-www-form-urlencoded"

        # 6) POST 登录
        resp = sess.post(
            POST_URL,
            data=data,
            headers=headers2,
            verify=False,
            allow_redirects=True,
        )

        print("[*] status:", resp.status_code)
        print("[*] final URL:", resp.url)

        # 简单判断一下是否登录成功
        url_lower = resp.url.lower()
        if (
            "/am/ui/login" in url_lower or
            "authfailed" in url_lower or
            "error" in url_lower or
            "fail" in url_lower
        ):
            print("[!] 看起来登录失败了")
        else:
            print("[+] 登录成功")


if __name__ == "__main__":
    login()
