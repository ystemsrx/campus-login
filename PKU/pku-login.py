# -*- coding: utf-8 -*-
import requests
from urllib.parse import quote

USERNAME = "your_id_here"
PASSWORD = "your_password_here"

LOGIN_PAGE = (
    "https://iaaa.pku.edu.cn/iaaa/oauth.jsp?"
    "appID=portal2017&appName=%E5%8C%97%E4%BA%AC%E5%A4%A7%E5%AD%A6%E6%A0%A1%E5%86%85%E4%BF%A1%E6%81%AF%E9%97%A8%E6%88%B7%E6%96%B0%E7%89%88"
    "&redirectUrl={redir}"
)

LOGIN_API = "https://iaaa.pku.edu.cn/iaaa/oauthlogin.do"

REDIR_URL = "https://portal.pku.edu.cn/portal2017/ssoLogin.do"


def get_login_page(session: requests.Session):
    """GET 登录页，取 JSESSIONID 用"""
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142 Safari/537.36"
    )
    url = LOGIN_PAGE.format(redir=quote(REDIR_URL, safe=""))
    r = session.get(url, headers={"User-Agent": ua})
    return r.status_code


def do_login(session: requests.Session):
    """POST 登录"""
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142 Safari/537.36"
    )
    data = {
        "appid": "portal2017",
        "userName": USERNAME,
        "password": PASSWORD,
        "randCode": "",
        "smsCode": "",
        "otpCode": "",
        "redirUrl": REDIR_URL,
    }

    headers = {
        "User-Agent": ua,
        "Origin": "https://iaaa.pku.edu.cn",
        "Referer": LOGIN_PAGE.format(redir=quote(REDIR_URL, safe="")),
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    }

    r = session.post(LOGIN_API, data=data, headers=headers)
    return r


def main():
    with requests.Session() as s:

        r = do_login(s)
        print("[*] POST status:", r.status_code)

        txt = r.text.strip()
        print("[*] response:", txt[:200], "..." if len(txt) > 200 else "")

        if '"success":true' in txt:
            print("[+] 登录成功")
        else:
            print("[!] 看起来登录失败了")


if __name__ == "__main__":
    main()
