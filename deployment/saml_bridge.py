"""Private pilot SAML bridge; shares the existing wallet over a Unix socket."""
import os
import json
from pathlib import Path
import signal
import socket
import stat
import threading
from federation import FederationServer
from revocation import configured_wallet

path = Path('/srv/openid/data/federation.sock')
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
bridge = FederationServer(path, configured_wallet('/srv/openid/data/wallet.sqlite', 'local-saml-bridge'), audience=audience)
try:
    stop.wait()
finally:
    bridge.close()
