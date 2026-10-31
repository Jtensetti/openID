"""Private pilot SAML bridge; shares the existing wallet over a Unix socket."""
import os
import json
from pathlib import Path
import signal
import socket
import stat
import threading
from federation import FederationServer
from notice_ipc import serve as serve_notices
from revocation import configured_wallet

path = Path(os.environ.get('OPENID_FEDERATION_SOCKET', '/srv/openid/data/federation.sock'))
if path.exists() or path.is_symlink():
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError('unexpected socket path')
    with socket.socket(socket.AF_UNIX) as probe:
        try:
            probe.connect(str(path))
        except ConnectionRefusedError:
            path.unlink()
        else:
            raise RuntimeError('bridge already running')
stop = threading.Event()
for sig in (signal.SIGTERM, signal.SIGINT):
    signal.signal(sig, lambda *_: stop.set())
origins_file = os.environ.get('OPENID_PILOT_ORIGINS')
audience = json.loads(Path(origins_file).read_text())['sp'] + '/sp' if origins_file else 'https://localhost:8444/sp'
group = int(os.environ['OPENID_FEDERATION_GROUP']) if os.environ.get('OPENID_FEDERATION_GROUP') else None
bridge = FederationServer(path, configured_wallet('/srv/openid/data/wallet.sqlite', 'local-saml-bridge'),
                          audience=audience, shared_group=group)
notice = None
worker = None
try:
    if os.environ.get('OPENID_NOTICE_SOCKET'):
        notice = serve_notices(os.environ['OPENID_NOTICE_SOCKET'], int(os.environ['OPENID_NOTICE_GROUP']), bridge.wallet)
        worker = threading.Thread(target=notice.serve_forever, daemon=True)
        worker.start()
    stop.wait()
finally:
    if notice is not None:
        notice.close()
    if worker is not None:
        worker.join(timeout=5)
    bridge.close()
