"""Local IPC for the SAML IdP and relying party; no enrollment or activation API."""
import io
import json
import os
from pathlib import Path
import socketserver
import stat
import threading
import qrcode
import qrcode.image.svg
from native import unique_object

class FederationServer:
    def __init__(self, path, wallet, audience='https://localhost:8444/sp', shared_group=None):
        self.path = Path(path)
        parent = self.path.parent
        if parent.is_symlink():
            raise ValueError('socket directory must not be a symlink')
        info = parent.stat()
        if shared_group is None:
            if info.st_mode & 0o077:
                raise ValueError('socket directory must be private (0700)')
        else:
            if (info.st_uid != os.getuid() or info.st_gid != shared_group or
                    info.st_mode & 0o777 != 0o710 or not (info.st_mode & stat.S_ISGID)):
                raise ValueError('socket directory must be owner-controlled mode 2710')
        if self.path.exists() or self.path.is_symlink(): raise ValueError('socket path already exists')
        self.wallet, self.audience = wallet, audience
        owner = self
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(5)
                try:
                    raw = self.rfile.readline(4097)
                    if len(raw) > 4096 or not raw.endswith(b'\n'): raise ValueError('message size')
                    data = json.loads(raw, object_pairs_hook=unique_object)
                    result = owner.dispatch(data)
                    self.wfile.write(json.dumps({'ok': True, 'result': result}, separators=(',', ':')).encode()+b'\n')
                except Exception:
                    try: self.wfile.write(b'{"ok":false}\n')
                    except OSError: pass
        self.server = socketserver.UnixStreamServer(str(self.path), Handler)
        os.chmod(self.path, 0o600 if shared_group is None else 0o660)
        if shared_group is not None and self.path.stat().st_gid != shared_group:
            self.server.server_close()
            self.path.unlink(missing_ok=True)
            raise ValueError('federation socket group mismatch')
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def dispatch(self, data):
        if not isinstance(data, dict) or data.get('audience') != self.audience: raise ValueError('audience')
        operation = data.get('operation')
        if operation == 'health' and set(data) == {'operation', 'audience'}:
            with self.wallet.transaction() as db:
                if db.execute('SELECT 1 FROM profiles LIMIT 1').fetchone(): self.wallet.vault.key()
            return {'state': 'READY'}
        if operation == 'start' and {'operation', 'audience', 'binding'} <= set(data) <= {'operation', 'audience', 'binding', 'signMessage', 'verification'}:
            return self.wallet.federation_start(data['binding'], self.audience, data.get('signMessage'), data.get('verification'))
        if operation == 'check' and set(data) == {'operation', 'audience', 'credentialId', 'subject', 'version'}:
            return self.wallet.federation_check(data['credentialId'], data['subject'], data['version'], self.audience)
        if operation in ('poll', 'consume', 'cancel', 'qr') and set(data) == {'operation', 'audience', 'id', 'secret', 'binding'}:
            result = self.wallet.federation_result('poll' if operation == 'qr' else operation,
                data['id'], data['secret'], data['binding'], self.audience)
            if operation == 'qr':
                if result['state'] != 'PENDING': raise ValueError('request unavailable')
                output = io.BytesIO()
                qrcode.make('openid://request/'+data['id'], image_factory=qrcode.image.svg.SvgPathImage,
                    box_size=8, border=4).save(output)
                return {'svg': output.getvalue().decode()}
            return result
        raise ValueError('operation')

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.path.unlink(missing_ok=True)
