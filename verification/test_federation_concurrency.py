"""The local SAML socket must serve another request while one client waits."""
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from federation import FederationServer


class FederationConcurrencyTests(unittest.TestCase):
    def test_slow_client_does_not_serialize_next_client(self):
        with tempfile.TemporaryDirectory() as directory:
            server = FederationServer(Path(directory)/'bridge.sock', object())
            self.addCleanup(server.close)
            entered = threading.Event(); release = threading.Event()
            def dispatch(request):
                if request['operation'] == 'slow':
                    entered.set()
                    if not release.wait(3): raise TimeoutError('test release')
                return {'state': 'READY'}
            server.dispatch = dispatch
            def send(operation):
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(2)
                    client.connect(str(server.path))
                    client.sendall(json.dumps({'operation': operation}).encode()+b'\n')
                    return json.loads(client.recv(4096))
            first = threading.Thread(target=lambda: send('slow'))
            first.start()
            try:
                self.assertTrue(entered.wait(2))
                self.assertEqual({'ok': True, 'result': {'state': 'READY'}}, send('fast'))
            finally:
                release.set(); first.join(3)
            self.assertFalse(first.is_alive())


if __name__ == '__main__': unittest.main()
