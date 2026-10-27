from pathlib import Path
import hashlib
import os
import tempfile
import unittest
from unittest.mock import patch

from image_surface import filesystem_evidence


class SurfaceEvidenceTests(unittest.TestCase):
    def test_component_hash_permissions_and_merged_usr_alias(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            (root/'usr/bin').mkdir(parents=True)
            (root/'bin').symlink_to(root/'usr/bin', target_is_directory=True)
            tool = root/'usr/bin/nsenter'; tool.write_bytes(b'synthetic tool'); tool.chmod(0o4755)
            (root/'usr/bin/mount').symlink_to('nsenter')
            (root/'usr/share/perl/Archive').mkdir(parents=True)
            (root/'usr/share/perl/Archive/Tar.pm').write_text('synthetic module')
            result = filesystem_evidence(root)
            self.assertTrue(result['completeWithinStatedScope'])
            self.assertEqual(result['roots'], ['/usr'])
            found = result['knownComponents']
            self.assertEqual(found['/usr/bin/nsenter']['sha256'], hashlib.sha256(b'synthetic tool').hexdigest())
            self.assertEqual(found['/usr/bin/nsenter']['mode'], '0o4755')
            self.assertTrue(found['/usr/bin/mount']['symlink'])
            self.assertEqual(found['/usr/bin/mount']['resolvedMode'], '0o4755')
            self.assertEqual(found['/usr/bin/mount']['resolvedPath'], '/usr/bin/nsenter')
            self.assertIn('/usr/share/perl/Archive/Tar.pm', found)
            self.assertNotIn('/usr/bin/systemd-homed', found)

    def test_inaccessible_tree_and_outside_symlink_cannot_claim_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve();(root/'usr').mkdir();(root/'outside').mkdir()
            (root/'usr/plugins').symlink_to(root/'outside', target_is_directory=True)
            result = filesystem_evidence(root)
            self.assertFalse(result['completeWithinStatedScope'])
            self.assertTrue(result['errors'])
            def denied(base, followlinks, onerror):
                onerror(PermissionError(13, 'denied', str(base)));return iter(())
            with patch('image_surface.os.walk', side_effect=denied):
                result = filesystem_evidence(root)
            self.assertFalse(result['completeWithinStatedScope'])
            self.assertEqual(result['errors'][0]['error'], 'PermissionError')

    def test_empty_scope_is_not_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertFalse(filesystem_evidence(Path(temp).resolve())['completeWithinStatedScope'])

    def test_broken_cyclic_and_non_directory_roots_are_reported(self):
        for kind in ('broken', 'cycle', 'file'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve(); (root/'usr').mkdir()
                if kind == 'file':
                    (root/'opt').write_text('not a code directory')
                else:
                    (root/'opt').symlink_to('opt' if kind == 'cycle' else 'missing')
                result = filesystem_evidence(root)
                self.assertFalse(result['completeWithinStatedScope'])
                self.assertEqual(result['errors'][0]['path'], '/opt')

    def test_unreadable_component_is_not_reported_absent_or_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); (root/'usr').mkdir()
            (root/'usr/nsenter').write_text('tool')
            with patch('image_surface.Path.open', side_effect=PermissionError('denied')):
                result = filesystem_evidence(root)
            self.assertFalse(result['completeWithinStatedScope'])
            self.assertEqual(result['errors'][0]['path'], '/usr/nsenter')

    def test_special_file_and_unsafe_component_links_are_not_read(self):
        for kind in ('outside', 'broken', 'cycle', 'fifo'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve(); (root/'usr').mkdir()
                path = root/'usr/nsenter'
                if kind == 'fifo':
                    os.mkfifo(path)
                else:
                    (root/'private').write_text('must not read')
                    path.symlink_to({'outside': '../private', 'broken': 'missing', 'cycle': 'nsenter'}[kind])
                with patch('image_surface.Path.open', side_effect=AssertionError('must not open')):
                    result = filesystem_evidence(root)
                self.assertFalse(result['completeWithinStatedScope'])
                self.assertTrue(result['errors'])
                self.assertNotIn('/usr/nsenter', result['knownComponents'])


if __name__ == '__main__':
    unittest.main()
