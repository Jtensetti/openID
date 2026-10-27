from pathlib import Path
import hashlib
import os
import tempfile
import unittest
from unittest.mock import patch

from image_surface import filesystem_evidence


class SurfaceEvidenceTests(unittest.TestCase):
    def test_whole_image_inspects_ssl_targets_and_components_outside_code_roots(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            (root/'usr/lib/ssl').mkdir(parents=True)
            for name in ('certs', 'private'):
                target = root/'etc/ssl'/name;target.mkdir(parents=True)
                (root/'usr/lib/ssl'/name).symlink_to(target, target_is_directory=True)
            (root/'etc/ssl/private/Archive').mkdir()
            module = root/'etc/ssl/private/Archive/Tar.pm'
            module.write_text('synthetic module outside conventional code roots')
            self.assertFalse(filesystem_evidence(root)['completeWithinStatedScope'])
            result = filesystem_evidence(root, whole_image=True)
            self.assertTrue(result['completeWithinStatedScope'])
            self.assertEqual(result['roots'], ['/'])
            self.assertEqual(result['excludedRoots'], ['/dev', '/proc', '/sys'])
            self.assertEqual(list(result['knownComponents']), ['/etc/ssl/private/Archive/Tar.pm'])
            self.assertEqual(result['knownComponents']['/etc/ssl/private/Archive/Tar.pm']['sha256'],
                             hashlib.sha256(module.read_bytes()).hexdigest())

    def test_whole_image_excludes_ephemeral_trees_and_rejects_aliases_into_them(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve();(root/'usr').mkdir()
            for name in ('dev', 'proc', 'sys'):
                (root/name).mkdir();(root/name/'nsenter').write_text('must not be read')
            with patch('image_surface.Path.open', side_effect=AssertionError('must not open')):
                result = filesystem_evidence(root, whole_image=True)
                self.assertTrue(result['completeWithinStatedScope'])
                self.assertEqual(result['knownComponents'], {})
                (root/'usr/nsenter').symlink_to(root/'proc/nsenter')
                (root/'usr/kernel').symlink_to(root/'sys', target_is_directory=True)
                result = filesystem_evidence(root, whole_image=True)
                self.assertFalse(result['completeWithinStatedScope'])
                self.assertEqual(len(result['errors']), 2)
                self.assertEqual(result['knownComponents'], {})

    def test_whole_image_does_not_hide_access_failures_or_follow_external_links(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            root = Path(temp).resolve();(root/'etc').mkdir()
            external = Path(outside)/'nsenter';external.write_text('must not be read')
            (root/'etc/nsenter').symlink_to(external)
            with patch('image_surface.Path.open', side_effect=AssertionError('must not open')):
                result = filesystem_evidence(root, whole_image=True)
            self.assertFalse(result['completeWithinStatedScope'])
            self.assertEqual(result['knownComponents'], {})
            def denied(base, followlinks, onerror):
                onerror(PermissionError(13, 'denied', str(base)));return iter(())
            with patch('image_surface.os.walk', side_effect=denied):
                result = filesystem_evidence(root, whole_image=True)
            self.assertFalse(result['completeWithinStatedScope'])
            self.assertEqual(result['errors'][0]['error'], 'PermissionError')

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
