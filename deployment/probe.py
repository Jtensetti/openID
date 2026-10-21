import http.client
import json
from pathlib import Path
import ssl
import sys
from urllib.parse import urlsplit

config = json.loads(Path(sys.argv[1]).read_text())
origin = urlsplit(config['origin'])
context = ssl.create_default_context(cafile=config['tlsCert'])
# Probe the explicit private listener; the external ingress deliberately hides health endpoints.
connection = http.client.HTTPSConnection(config['bind'], config.get('listenPort', origin.port), context=context, timeout=3)
try:
    connection.request('GET', '/health/ready', headers={'Host': origin.netloc})
    response = connection.getresponse()
    if response.status != 200 or json.load(response) != {'status': 'READY'}: raise SystemExit(1)
finally:
    connection.close()
