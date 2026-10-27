from pathlib import Path
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from file_privileges import apply, scan, verify


class FilePrivilegeTests(unittest.TestCase):
    def fixture(self, root, name='usr/bin/tool', mode=0o6755):
        path = root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'synthetic executable')
        path.chmod(mode)
        return path

    def test_removal_preserves_content_owner_and_other_modes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            files = [self.fixture(root, 'usr/bin/tool'+str(n), mode)
                     for n, mode in enumerate((0o4755, 0o2750, 0o7644))]
            report = apply(root)
            self.assertEqual(len(report['changed']), 3)
            self.assertEqual([stat.S_IMODE(p.stat().st_mode) for p in files], [0o755, 0o750, 0o1644])
            self.assertTrue(all(p.read_bytes() == b'synthetic executable' for p in files))
            self.assertEqual(verify(root, report)['buildFilesVerified'], 3)

    def test_symlinks_and_directory_setgid_are_not_changed(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            root = Path(temp).resolve()
            target = self.fixture(Path(outside).resolve())
            (root/'alias').symlink_to(target)
            (root/'directory').symlink_to(target.parent, target_is_directory=True)
            (root/'real').mkdir(); (root/'real').chmod(0o2755)
            self.assertEqual(apply(root)['changed'], [])
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o6755)
            self.assertEqual(stat.S_IMODE((root/'real').stat().st_mode), 0o2755)

    def test_hardlink_aliases_change_together_and_report_verifies(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); path = self.fixture(root)
            os.link(path, root/'other-name')
            report = apply(root)
            self.assertEqual(len(report['changed']), 1)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)
            self.assertEqual(verify(root, report)['buildFilesVerified'], 1)

    def test_virtual_roots_excluded_but_nested_names_and_hidden_files_scanned(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            excluded = self.fixture(root, 'proc/virtual')
            self.fixture(root, 'opt/proc/.tool')
            report = apply(root)
            self.assertEqual([x['path'] for x in report['changed']], ['/opt/proc/.tool'])
            self.assertEqual(stat.S_IMODE(excluded.stat().st_mode), 0o6755)

    def test_traversal_error_fails_instead_of_claiming_complete(self):
        def denied(root, followlinks, onerror):
            onerror(PermissionError('denied'))
        with tempfile.TemporaryDirectory() as temp, patch('file_privileges.os.walk', side_effect=denied):
            with self.assertRaises(PermissionError):
                scan(Path(temp))

    def test_permission_change_failure_propagates(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); self.fixture(root)
            with patch('file_privileges.os.fchmod', side_effect=PermissionError('denied')):
                with self.assertRaises(PermissionError):
                    apply(root)

    def test_added_privileged_file_and_changed_content_are_rejected(self):
        for change in ('extra', 'content', 'symlink'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve(); path = self.fixture(root); report = apply(root)
                if change == 'extra':
                    self.fixture(root, 'etc/unexpected')
                elif change == 'content':
                    path.write_bytes(b'replaced executable')
                else:
                    target = root/'target'; path.rename(target); path.symlink_to(target)
                with self.assertRaises(ValueError):
                    verify(root, report)

    def test_tampered_helper_and_report_path_are_rejected(self):
        for change in ('helper', 'path', 'duplicate'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve(); self.fixture(root); report = apply(root)
                if change == 'helper': report['helperSHA256'] = '0'*64
                elif change == 'path': report['changed'][0]['path'] = '/../outside'
                else: report['changed'].append(report['changed'][0].copy())
                with self.assertRaises(ValueError): verify(root, report)


if __name__ == '__main__':
    unittest.main()
