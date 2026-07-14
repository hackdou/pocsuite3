from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
    CEye,
    get_listener_ip, get_listener_port, REVERSE_PAYLOAD
)

minimum_version_required('1.9.11')


class POC(POCBase):
    name = 'HiKVISION 综合安防管理平台 env 信息泄漏漏洞'
    vulType = 'Command Execution'
    desc = 'Vulnerability description'
    pocDesc = 'User manual of poc'
    dork = {'fofa': ''}

    def _exploit(self):
        pass

    def _verify(self):
        return
        pass


register_poc(POC)
