import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from prepare_source import prepare


class SourceBindingTests(unittest.TestCase):
    def fixture(self, root):
        source, patch = root/'source', root/'patch'
        source.mkdir(); patch.mkdir(); (source/'internal/vault').mkdir(parents=True)
        files={}
        for name,replacement in {'go.mod':'openbao.go.mod','go.sum':'openbao.go.sum',
                                 'internal/vault/login_mfa.go':'openbao.login_mfa.go'}.items():
            (source/name).write_bytes(b'upstream'); (patch/replacement).write_bytes(b'candidate')
            files[name]={'replacement':replacement,'upstreamSHA256':hashlib.sha256(b'upstream').hexdigest(),
                         'modifiedSHA256':hashlib.sha256(b'candidate').hexdigest()}
        (patch/'sources.lock.json').write_text(json.dumps({'sourceFiles':files}))
        (patch/'tjipp_mfa_test.go').write_bytes(b'reject unavailable method')
        return source,patch

    def test_all_sources_checked_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            source,patch=self.fixture(Path(d)); (source/'internal/vault/login_mfa.go').write_bytes(b'changed')
            with self.assertRaises(ValueError): prepare(source,patch)
            self.assertEqual((source/'go.mod').read_bytes(),b'upstream')

    def test_replacement_tamper_symlink_or_incomplete_lock_rejected(self):
        for mode in ('tamper','symlink','missing','traversal'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as d:
                source,patch=self.fixture(Path(d)); path=patch/'sources.lock.json'; value=json.loads(path.read_text())
                if mode=='tamper': (patch/'openbao.go.sum').write_bytes(b'changed')
                if mode=='symlink':
                    (patch/'openbao.go.sum').unlink();(patch/'openbao.go.sum').symlink_to(patch/'openbao.go.mod')
                if mode=='missing': del value['sourceFiles']['go.sum']
                if mode=='traversal': value['sourceFiles']['go.sum']['replacement']='../go.sum'
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError): prepare(source,patch)
                self.assertEqual((source/'go.mod').read_bytes(),b'upstream')

    def test_exact_patch_and_rejecting_test_are_installed(self):
        with tempfile.TemporaryDirectory() as d:
            source,patch=self.fixture(Path(d));prepare(source,patch)
            self.assertEqual((source/'internal/vault/login_mfa.go').read_bytes(),b'candidate')
            self.assertEqual((source/'internal/vault/tjipp_mfa_test.go').read_bytes(),b'reject unavailable method')


if __name__=='__main__': unittest.main()
