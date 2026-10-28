"""Shared-registry CRL configuration boundary with generated files."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class ClusterRevocationConfigTests(unittest.TestCase):
    def test_proofing_accepts_only_an_existing_absolute_crl_path(self):
        from cluster_serve import config_file
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            secret=root/'secret';secret.write_text('a'*43);secret.chmod(0o600)
            config=dict(role='proofing',bind='127.0.0.1',port=8765,origin='https://localhost:8765',workers=1,
                baoAddress='https://localhost:8200',team='A'*10,bundle='se.openid.PassportCapture',developmentAttestation=True)
            config.update({field:str(secret) for field in ('databaseFile','baoTokenFile','baoCA','tlsCert','tlsKey',
                'pairingFile','metricsFile','csca','jar')})
            path=root/'config.json'
            # Only TLS parsing is replaced here; this is a configuration boundary test.
            with patch('cluster_serve.ssl.SSLContext'):
                for extra in ({},{'cscaCrl':str(secret)},{'newRegistrationsEnabled':False}):
                    path.write_text(json.dumps(config|extra))
                    self.assertEqual(config|extra,config_file(path))
                path.write_text(json.dumps(config|{'newRegistrationsEnabled':True}))
                with self.assertRaisesRegex(ValueError,'explicit enrollment policy'):config_file(path)
                from test_enrollment_policy import fixture_policy
                import time
                policy=fixture_policy();policy['notice'].update(notBefore=int(time.time())-60,notAfter=int(time.time())+3600)
                notice=root/'notice.json';notice.write_text(json.dumps(policy));notice.chmod(0o600)
                enabled=config|{'newRegistrationsEnabled':True,'enrollmentPolicyFile':str(notice)}
                path.write_text(json.dumps(enabled));self.assertEqual(enabled,config_file(path))
                # An expired/removed collection policy must not block existing
                # status or withdrawal once collection has been disabled.
                notice.unlink();paused=enabled|{'newRegistrationsEnabled':False}
                path.write_text(json.dumps(paused));self.assertEqual(paused,config_file(path))
                path.write_text(json.dumps(enabled))
                with self.assertRaises(OSError):config_file(path)
                for value in ('false', 0, 1, None):
                    path.write_text(json.dumps(config|{'newRegistrationsEnabled':value}))
                    with self.assertRaisesRegex(ValueError,'registration flag'):config_file(path)
                for crl in ('relative.crl',str(root/'missing.crl')):
                    path.write_text(json.dumps(config|{'cscaCrl':crl}))
                    with self.assertRaisesRegex(ValueError,'absolute existing path'):config_file(path)
                wallet={key:value for key,value in config.items()
                    if key not in ('team','bundle','developmentAttestation','csca','jar')}
                path.write_text(json.dumps(wallet|{'role':'wallet','cscaCrl':str(secret)}))
                with self.assertRaisesRegex(ValueError,'configuration fields'):config_file(path)


if __name__=='__main__': unittest.main()
