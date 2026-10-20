import http.client
import json
from pathlib import Path
import socket
import ssl
import sys
from urllib.parse import urlsplit

try:
    config=json.loads(Path(sys.argv[1]).read_text());origin=urlsplit(config['origin'])
    context=ssl.create_default_context(cafile=config['tlsCert'])
    connection=http.client.HTTPSConnection(origin.hostname,config['port'],context=context,timeout=4)
    connection.sock=context.wrap_socket(socket.create_connection((config['bind'],config['port']),timeout=4),server_hostname=origin.hostname)
    connection.request('GET','/health/ready',headers={'Host':origin.netloc})
    response=connection.getresponse();body=response.read(4097);connection.close()
    assert response.status==200 and json.loads(body)=={'status':'READY'}
except Exception:raise SystemExit(1)
