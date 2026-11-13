"""Private component readiness; never prints profiles, sessions or credentials."""
import http.client
from html.parser import HTMLParser
import json
from pathlib import Path
import ssl
import stat
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'verification'))
from aws_credential_process import load
from federation_config import read_origins
from ipc_support import request


def sp_ready(body):
    class Marker(HTMLParser):
        def __init__(self):
            super().__init__();self.current=None;self.markers=[]
        def handle_starttag(self,tag,attrs):
            if tag=='main':
                if self.current is not None:raise ValueError('nested readiness marker')
                self.current=[]
        def handle_endtag(self,tag):
            if tag=='main' and self.current is not None:
                self.markers.append(''.join(self.current));self.current=None
        def handle_data(self,text):
            if self.current is not None:self.current.append(text)
    parser=Marker();parser.feed(body.decode('utf-8'));parser.close()
    return parser.current is None and parser.markers==['READY']


def main():
    try:
        name = sys.argv[1]
        if name == 'continuity':
            load('/srv/openid/aws/session.json')
            if request('/srv/openid/continuity-ipc/continuity.sock', {'operation': 'health'}) != {'state': 'READY'}:
                raise ValueError('controller unavailable')
        elif name == 'bridge':
            audience = read_origins('/srv/openid/origins.json')['sp'] + '/sp'
            if request('/srv/openid/federation-ipc/federation.sock', {'operation': 'health', 'audience': audience}) != {'state': 'READY'}:
                raise ValueError('bridge unavailable')
            if not stat.S_ISSOCK(Path('/srv/openid/notice-ipc/notice.sock').stat().st_mode):
                raise ValueError('notice socket unavailable')
        elif name == 'notice-exporter':
            load('/srv/openid/aws/session.json')
            if not stat.S_ISSOCK(Path('/srv/openid/notice-ipc/notice.sock').stat().st_mode):
                raise ValueError('notice socket unavailable')
        elif name in ('idp', 'sp'):
            origin = urlsplit(read_origins('/srv/openid/origins.json')[name])
            context = ssl.create_default_context(cafile='/srv/openid/health-ca.pem')
            connection = http.client.HTTPSConnection('localhost', 9443 if name == 'idp' else 9444, context=context, timeout=3)
            try:
                path = '/phone/page.css' if name == 'idp' else '/health/ready'
                connection.request('GET', path, headers={'Host': origin.netloc})
                response = connection.getresponse(); body = response.read(16385)
                if response.status != 200 or len(body) > 16384:
                    raise ValueError('federation unavailable')
                if name == 'sp' and not sp_ready(body): raise ValueError('SP storage unavailable')
            finally: connection.close()
        else: raise ValueError('unknown component')
        return 0
    except Exception:
        return 1


if __name__ == '__main__':
    sys.exit(main())
