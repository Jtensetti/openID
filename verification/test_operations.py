import math
import unittest
from evaluate_biometrics import evaluate
from monitor import update

class OperationsTests(unittest.TestCase):
    def test_alert_debounce_and_recovery(self):
        state={}
        for expected in (False,False,True,False):
            state,changed=update(state,False);self.assertEqual(expected,changed)
        state,changed=update(state,True);self.assertTrue(changed);self.assertFalse(state['alert'])
        self.assertFalse(update(state,True)[1])

    def rows(self):
        return [{'sample':str(i),'subject':str(i)+(';other' if kind=='impostor' else ''),'partition':'evaluation','kind':kind,'score':str(score)} for i,(kind,score) in enumerate(
            [('genuine',.8),('impostor',.7),('bona_fide',.6),('attack',.2)])]

    def test_fixed_holdout_metrics_and_nonzero_uncertainty(self):
        result=evaluate(self.rows(),.5,.5)['metrics']
        self.assertEqual(1,result['FMR']['errors']);self.assertEqual(0,result['APCER']['errors'])
        self.assertGreater(result['APCER']['wilson95'][1],0)
        self.assertEqual(4,sum(m['samples'] for m in result.values()))

    def test_leakage_duplicates_missing_classes_and_invalid_scores_fail(self):
        for changes in ({'score':'NaN'},{'score':'2'},{'kind':'unknown'}):
            rows=self.rows();rows[0].update(changes)
            with self.assertRaises(ValueError):evaluate(rows,.5,.5)
        rows=self.rows();rows.append(dict(rows[0]))
        with self.assertRaises(ValueError):evaluate(rows,.5,.5)
        rows=self.rows();rows.append(dict(rows[0],sample='extra',partition='calibration'))
        with self.assertRaises(ValueError):evaluate(rows,.5,.5)
        with self.assertRaises(ValueError):evaluate(self.rows()[:-1],.5,.5)
        with self.assertRaises(ValueError):evaluate(self.rows(),math.nan,.5)
        rows=self.rows();rows.append(dict(rows[0],sample='other',subject='other',partition='calibration'))
        with self.assertRaises(ValueError):evaluate(rows,.5,.5)

if __name__=='__main__':unittest.main()

class TransportTests(unittest.TestCase):
    def test_tls_health_and_acknowledged_alert_without_identifiers(self):
        from http.server import BaseHTTPRequestHandler,HTTPServer
        from pathlib import Path
        import tempfile,subprocess,ssl,threading,json
        from monitor import notify,read_status
        with tempfile.TemporaryDirectory() as directory:
            cert,key=Path(directory)/'cert',Path(directory)/'key'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
                '-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            seen=[]
            class Handler(BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def do_GET(self):
                    self.send_response(200);self.end_headers();self.wfile.write(b'{"status":"READY"}')
                def do_POST(self):
                    body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    seen.append(body)
                    self.send_response(204 if self.headers.get('Authorization')=='Bearer test-token' else 403);self.end_headers()
            server=HTTPServer(('127.0.0.1',0),Handler)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                origin='https://localhost:'+str(server.server_port)
                self.assertTrue(read_status(origin,cert))
                notify(origin+'/alert',cert,'test-token','wallet','UNAVAILABLE')
                self.assertEqual({'service':'wallet','state':'UNAVAILABLE'},seen[0])
                with self.assertRaises(RuntimeError):notify(origin+'/alert',cert,'wrong','wallet','RECOVERED')
                self.assertFalse(read_status(origin,None))
            finally:server.shutdown();server.server_close();thread.join(timeout=2)
