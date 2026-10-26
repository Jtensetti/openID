"""File-system fault tests use a verifier double; CLI tests use real signed Java fixtures."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock,patch

from crl_maintenance import Verifier,check,install,read_regular,MAX_BYTES


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
        self.destination=self.root/'active.crl';self.candidate=self.root/'candidate.crl'
        self.destination.write_bytes(b'old');self.candidate.write_bytes(b'new')
        self.verifier=Mock(return_value={'status':'VERIFIED','sha256':hashlib.sha256(b'new').hexdigest(),
            'issuers':1,'validUntil':5000})
        self.install=lambda **kwargs:install(self.candidate,self.destination,self.verifier,clock=lambda:1000,**kwargs)

    def test_install_checks_exact_bytes_and_preserves_private_mode(self):
        self.assertEqual('INSTALLED',self.install()['status'])
        self.verifier.assert_called_once_with(b'new',b'old')
        self.assertEqual(b'new',self.destination.read_bytes())
        self.assertEqual(0o600,self.destination.stat().st_mode & 0o777)
        self.assertFalse(list(self.root.glob('.crl-*')))

    def test_rejected_candidate_does_not_change_installed_bytes(self):
        self.verifier.side_effect=ValueError('rejected')
        with self.assertRaises(ValueError):self.install()
        self.assertEqual(b'old',self.destination.read_bytes())

    def test_initialization_is_explicit_and_cannot_overwrite_existing_state(self):
        with self.assertRaises(ValueError):self.install(initialize=True)
        self.destination.unlink()
        with self.assertRaises(ValueError):self.install()
        self.verifier.assert_not_called()
        self.assertEqual('INSTALLED',self.install(initialize=True)['status'])
        self.verifier.assert_called_once_with(b'new',None)

    def test_identical_update_is_validated_but_not_rewritten(self):
        self.candidate.write_bytes(b'old')
        original=self.destination.stat().st_ino
        self.assertEqual('UNCHANGED',self.install()['status'])
        self.assertEqual(original,self.destination.stat().st_ino)
        self.verifier.assert_called_once_with(b'old',b'old')

    def test_write_or_replace_failure_leaves_old_file(self):
        for target in ('crl_maintenance.os.fsync','crl_maintenance.os.replace'):
            with self.subTest(target=target),patch(target,side_effect=OSError('failure')):
                with self.assertRaises(OSError):self.install()
            self.assertEqual(b'old',self.destination.read_bytes())
            self.assertFalse(list(self.root.glob('.crl-*')))

    def test_expiry_during_disk_write_cannot_promote_list(self):
        clock=Mock(side_effect=[1000,4700])
        with self.assertRaises(ValueError):install(self.candidate,self.destination,self.verifier,clock=clock)
        self.assertEqual(b'old',self.destination.read_bytes())

    def test_directory_sync_failure_never_reinstates_an_old_list(self):
        with patch('crl_maintenance.os.fsync',side_effect=[None,OSError('directory sync failed')]):
            with self.assertRaises(OSError):self.install()
        # Rename already happened: report failure, inspect/retry, never roll back.
        self.assertEqual(b'new',self.destination.read_bytes())
        self.assertEqual('UNCHANGED',self.install()['status'])
        self.assertFalse(list(self.root.glob('.crl-*')))

    def test_concurrent_update_refuses_without_running_verifier(self):
        lock=Path(str(self.destination)+'.lock');lock.touch(mode=0o600)
        with lock.open('wb') as stream:
            fcntl.flock(stream.fileno(),fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.install()
        self.verifier.assert_not_called()

    def test_symlink_fifo_and_oversize_candidates_are_rejected(self):
        link=self.root/'link';link.symlink_to(self.candidate)
        fifo=self.root/'fifo';os.mkfifo(fifo)
        huge=self.root/'huge'
        with huge.open('wb') as stream:stream.truncate(MAX_BYTES+1)
        for path in (link,fifo,huge):
            with self.subTest(path=path.name),self.assertRaises((OSError,ValueError)):read_regular(path)

    def test_destination_and_lock_symlinks_never_touch_the_target(self):
        self.destination.unlink();self.destination.symlink_to(self.candidate)
        with self.assertRaises(OSError):self.install()
        self.assertEqual(b'new',self.candidate.read_bytes())
        self.destination.unlink();self.destination.write_bytes(b'old')
        lock=Path(str(self.destination)+'.lock');lock.unlink();lock.symlink_to(self.candidate)
        with self.assertRaises(OSError):self.install()
        self.assertEqual(b'new',self.candidate.read_bytes())

    def test_writable_directory_or_installed_file_is_rejected(self):
        self.root.chmod(0o777)
        with self.assertRaises(ValueError):self.install()
        self.root.chmod(0o700);self.destination.chmod(0o666)
        with self.assertRaises(ValueError):self.install()
        self.verifier.assert_not_called()

    def test_health_warning_and_expiry_boundaries(self):
        self.assertEqual('CURRENT',check(self.destination,self.verifier,warn_before=100,clock=lambda:4899)['status'])
        self.assertEqual('EXPIRING',check(self.destination,self.verifier,warn_before=100,clock=lambda:4900)['status'])
        with self.assertRaises(ValueError):check(self.destination,self.verifier,clock=lambda:5000)

    def test_python_boundary_rejects_wrong_digest_and_malformed_result(self):
        verifier=Verifier('java','test.jar','trust.pem')
        for value in ({'status':'VERIFIED','sha256':'0'*64,'issuers':1,'validUntil':5000},
                      {'status':'VERIFIED'}, {'status':'REJECTED'}):
            with patch('crl_maintenance.subprocess.run',return_value=Mock(returncode=0,stdout=json.dumps(value).encode())):
                with self.assertRaises(ValueError):verifier(b'new',b'old')


@unittest.skipUnless(os.environ.get('PROOFING_FIXTURES') and os.environ.get('PROOFING_JAVA'),'requires signed Java fixtures')
class SignedCliTests(unittest.TestCase):
    def test_real_verifier_installs_update_rejects_rollback_and_reports_expiry(self):
        fixtures=Path(os.environ['PROOFING_FIXTURES'])
        verifier=Verifier(os.environ['PROOFING_JAVA'],Path(__file__).resolve().parents[1]/'prototype/target/isolated-eid-lab.jar',fixtures/'csca.der')
        with tempfile.TemporaryDirectory() as directory:
            destination=Path(directory).resolve()/'active.crl'
            self.assertEqual('INSTALLED',install(fixtures/'csca.crl',destination,verifier,initialize=True)['status'])
            self.assertEqual('INSTALLED',install(fixtures/'csca-next.crl',destination,verifier)['status'])
            current=destination.read_bytes()
            with self.assertRaises(ValueError):install(fixtures/'csca.crl',destination,verifier)
            self.assertEqual(current,destination.read_bytes())
            self.assertEqual('EXPIRING',check(destination,verifier)['status'])
            # A malformed input never reaches the installed file.
            bad=Path(directory)/'bad';bad.write_bytes(b'not a CRL')
            with self.assertRaises(ValueError):install(bad,destination,verifier)
            self.assertEqual(current,destination.read_bytes())


if __name__=='__main__':unittest.main()
