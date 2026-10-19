# SPDX-License-Identifier: GPL-2.0-only
"""Integration tests with disposable Git repositories, without kernel builds."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import qla2xxx
import qla2xxx_audit as audit


class QlaTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='qla test ')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.linux = self.root / 'linux repo'
        self.scst = self.root / 'scst repo'
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                        GIT_AUTHOR_NAME='Upstream Author', GIT_AUTHOR_EMAIL='author@example.com',
                        GIT_COMMITTER_NAME='Test Maintainer', GIT_COMMITTER_EMAIL='test@example.com',
                        GIT_AUTHOR_DATE='2025-01-02T03:04:05+00:00',
                        GIT_COMMITTER_DATE='2025-01-02T03:04:05+00:00')
        self.environment = patch.dict(os.environ, self.env, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        for repo in (self.linux, self.scst):
            repo.mkdir()
            self.git(repo, 'init', '-q', '--initial-branch=main')
        self.base = self.commit(self.linux, 'Base', {
            qla2xxx.UPSTREAM + 'qla.c': 'base\n',
            qla2xxx.UPSTREAM + 'Makefile': 'obj-m := old.o\n',
            qla2xxx.TRACE: 'trace old\n',
        })
        self.scst_base = self.commit(self.scst, 'qla2x00t-32gbit: Base\n\n'
                                    f'[ commit {self.base[:12]} upstream ]', {
            qla2xxx.DEST + 'qla.c': 'base\n',
            qla2xxx.DEST + 'Makefile_in-tree': 'obj-m := old.o\n',
            qla2xxx.DEST + 'Makefile': 'SCST out-of-tree rules\n',
            qla2xxx.DEST + qla2xxx.TRACE: 'trace old\n',
            qla2xxx.DEST + 'qla2x00-target/adapter.c': 'SCST adapter\n',
        })

    def git(self, repo, *args, check=True):
        result = subprocess.run(['git', '-C', str(repo), *args], env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check and result.returncode:
            self.fail(result.stderr.decode(errors='replace'))
        return result

    def commit(self, repo, message, files):
        for name, content in files.items():
            path = repo / name
            if content is None:
                path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content.encode() if isinstance(content, str) else content)
        self.git(repo, 'add', '-A')
        self.git(repo, 'commit', '-q', '-m', message)
        return self.git(repo, 'rev-parse', 'HEAD').stdout.decode().strip()

    def invoke(self, command, *options, ok=True):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = qla2xxx.main([command, '--linux', str(self.linux), '--scst', str(self.scst),
                                   '--to', 'HEAD', *map(str, options)])
        if ok:
            self.assertEqual(status, 0, stderr.getvalue())
        else:
            self.assertNotEqual(status, 0, stdout.getvalue())
        return stdout.getvalue(), stderr.getvalue()

    def history(self, *options):
        return json.loads(self.invoke('history', '--json', *options)[0])

    def output(self, name='export'):
        return self.root / name

    def export(self, *options):
        return json.loads(self.invoke('export', '--json', '--output', self.output(), *options)[0])

    def test_infers_marker_ignoring_later_local_change_and_detects_recorded_import(self):
        first = self.commit(self.linux, 'scsi: qla2xxx: First', {qla2xxx.UPSTREAM + 'qla.c': 'one\n'})
        self.commit(self.scst, f'qla2x00t-32gbit: First\n\n[ commit {first} upstream ]',
                    {qla2xxx.DEST + 'qla.c': 'one\n'})
        self.commit(self.scst, 'qla2x00t-32gbit: Local adaptation',
                    {qla2xxx.DEST + 'local.c': 'local\n'})
        second = self.commit(self.linux, 'scsi: qla2xxx: Second',
                             {qla2xxx.UPSTREAM + 'qla.c': 'two\n'})
        report = self.history()
        self.assertEqual(report['linux_base'], first)
        self.assertEqual([e['upstream'] for e in report['commits']], [second])
        report = self.history('--since', self.base)
        self.assertEqual([e['status'] for e in report['commits']], ['recorded', 'pending'])

    def test_export_applies_paths_binary_rename_author_date_and_provenance(self):
        first = self.commit(self.linux, 'scsi: qla2xxx: Change all mappings\n\n'
                            'Keep the explanation.\n\nSigned-off-by: Upstream Author <author@example.com>', {
            qla2xxx.UPSTREAM + 'qla.c': 'new\n',
            qla2xxx.UPSTREAM + 'Makefile': 'obj-m := new.o\n',
            qla2xxx.TRACE: 'trace new\n',
            qla2xxx.UPSTREAM + 'firmware.bin': b'\0\xffbinary\0',
        })
        second = self.commit(self.linux, 'scsi: qla2xxx: Rename file', {
            qla2xxx.UPSTREAM + 'qla.c': None,
            qla2xxx.UPSTREAM + 'new name.c': 'new\n',
        })
        self.commit(self.linux, 'scsi: qla2xxx: Trace only', {qla2xxx.TRACE: 'trace latest\n'})
        before = [self.git(repo, 'status', '--porcelain').stdout for repo in (self.linux, self.scst)]
        report = self.export()
        self.assertEqual(report['patch_count'], 3)
        self.assertEqual(before, [self.git(repo, 'status', '--porcelain').stdout
                                 for repo in (self.linux, self.scst)])
        self.assertEqual(self.git(self.scst, 'rev-parse', 'HEAD').stdout.decode().strip(), self.scst_base)
        for filename in (self.output() / 'series').read_text().splitlines():
            self.git(self.scst, 'am', str(self.output() / filename))
        self.assertEqual((self.scst / (qla2xxx.DEST + 'Makefile')).read_text(), 'SCST out-of-tree rules\n')
        self.assertEqual((self.scst / (qla2xxx.DEST + 'Makefile_in-tree')).read_text(), 'obj-m := new.o\n')
        self.assertEqual((self.scst / (qla2xxx.DEST + qla2xxx.TRACE)).read_text(), 'trace latest\n')
        self.assertEqual((self.scst / (qla2xxx.DEST + 'firmware.bin')).read_bytes(), b'\0\xffbinary\0')
        self.assertFalse((self.scst / (qla2xxx.DEST + 'qla.c')).exists())
        self.assertEqual((self.scst / (qla2xxx.DEST + 'new name.c')).read_text(), 'new\n')
        log = self.git(self.scst, 'log', '--format=%an <%ae>%n%aI%n%B', self.scst_base + '..HEAD').stdout.decode()
        self.assertIn('Upstream Author <author@example.com>', log)
        self.assertIn(self.git(self.linux, 'show', '-s', '--format=%aI', first).stdout.decode().strip(), log)
        self.assertIn('qla2x00t-32gbit: Change all mappings', log)
        self.assertIn(f'[ commit {first} upstream ]', log)
        self.assertIn(f'[ commit {second} upstream ]', log)
        self.assertIn('Signed-off-by: Upstream Author <author@example.com>', log)
        self.assertEqual(self.history('--since', self.base)['counts'], {'recorded': 3})

    def test_unicode_long_subject_and_author_round_trip(self):
        self.env['GIT_AUTHOR_NAME'] = 'Автор Патча'
        subject = 'Исправить ' + 'длинное описание ' * 10
        self.commit(self.linux, 'scsi: qla2xxx: ' + subject + '\n\nОписание изменения.',
                    {qla2xxx.UPSTREAM + 'qla.c': 'unicode\n'})
        self.export()
        self.git(self.scst, 'am', str(next(self.output().glob('*.patch'))))
        self.assertEqual(self.git(self.scst, 'show', '-s', '--format=%an').stdout.decode().strip(),
                         'Автор Патча')
        self.assertEqual(self.git(self.scst, 'show', '-s', '--format=%s').stdout.decode().strip(),
                         'qla2x00t-32gbit: ' + subject.strip())
        self.assertIn('Описание изменения.', self.git(self.scst, 'show', '-s', '--format=%B').stdout.decode())

    def test_patch_header_mapping_never_rewrites_hunk_content(self):
        # Deleted source text can look exactly like a --- patch header.
        old = '-- a/qla2x00t-32gbit/Makefile\n'
        self.commit(self.linux, 'scsi: qla2xxx: Add header-like text',
                    {qla2xxx.UPSTREAM + 'qla.c': old})
        self.commit(self.linux, 'scsi: qla2xxx: Remove header-like text',
                    {qla2xxx.UPSTREAM + 'qla.c': 'ordinary text\n'})
        self.export()
        for filename in (self.output() / 'series').read_text().splitlines():
            self.git(self.scst, 'am', str(self.output() / filename))
        self.assertEqual((self.scst / (qla2xxx.DEST + 'qla.c')).read_text(), 'ordinary text\n')

    def test_real_merge_resolution_is_exported_for_review(self):
        self.git(self.linux, 'checkout', '-q', '-b', 'side')
        side = self.commit(self.linux, 'scsi: qla2xxx: Side', {qla2xxx.UPSTREAM + 'qla.c': 'side\n'})
        self.git(self.linux, 'checkout', '-q', 'main')
        main = self.commit(self.linux, 'scsi: qla2xxx: Main', {qla2xxx.UPSTREAM + 'qla.c': 'main\n'})
        result = self.git(self.linux, 'merge', '--no-ff', 'side', '-m', 'Merge side', check=False)
        self.assertNotEqual(result.returncode, 0)
        merge = self.commit(self.linux, 'Merge resolved', {qla2xxx.UPSTREAM + 'qla.c': 'main and side\n'})
        report = self.export()
        self.assertEqual({e['upstream'] for e in report['commits']}, {side, main, merge})
        entry = report['commits'][-1]
        self.assertTrue(entry['merge_resolution'])
        self.assertEqual(report['review_count'], 1)
        self.assertEqual(report['patch_count'], 2)
        self.assertIn(b'main and side', (self.output() / entry['artifact']).read_bytes())
        self.assertNotIn('remerge', (self.output() / 'series').read_text())

    def test_clean_merge_is_still_reported(self):
        self.git(self.linux, 'checkout', '-q', '-b', 'side')
        self.commit(self.linux, 'scsi: qla2xxx: Side', {qla2xxx.UPSTREAM + 'other.c': 'side\n'})
        self.git(self.linux, 'checkout', '-q', 'main')
        self.commit(self.linux, 'scsi: qla2xxx: Main', {qla2xxx.UPSTREAM + 'qla.c': 'main\n'})
        self.git(self.linux, 'merge', '--no-ff', 'side', '-m', 'Merge side')
        merges = [e for e in self.history()['commits'] if e['kind'] == 'merge']
        # Full-history may omit a TREESAME merge with no relevant contribution;
        # this merge changes the selected subtree relative to both parents.
        self.assertEqual(len(merges), 1)
        self.assertFalse(merges[0]['merge_resolution'])

    def test_merge_that_discards_a_side_change_remains_visible(self):
        self.git(self.linux, 'checkout', '-q', '-b', 'side')
        side = self.commit(self.linux, 'scsi: qla2xxx: Side', {qla2xxx.UPSTREAM + 'qla.c': 'side\n'})
        self.git(self.linux, 'checkout', '-q', 'main')
        main = self.commit(self.linux, 'scsi: qla2xxx: Main', {qla2xxx.UPSTREAM + 'qla.c': 'main\n'})
        self.git(self.linux, 'merge', '--no-ff', 'side', '-m', 'Merge side', check=False)
        merge = self.commit(self.linux, 'Keep main version', {qla2xxx.UPSTREAM + 'qla.c': 'main\n'})
        report = self.history()
        self.assertEqual({e['upstream'] for e in report['commits']}, {side, main, merge})
        self.assertTrue(report['commits'][-1]['merge_resolution'])

    def test_mixed_commit_is_not_in_automatic_series_and_keeps_original(self):
        self.commit(self.linux, 'scsi: Shared API change', {
            qla2xxx.UPSTREAM + 'qla.c': 'new API\n', 'include/scsi/api.h': 'external dependency\n'})
        report = self.export()
        self.assertEqual(report['patch_count'], 0)
        entry = report['commits'][0]
        self.assertEqual(entry['outside_paths'], ['include/scsi/api.h'])
        self.assertIn('review/', entry['artifact'])
        self.assertNotIn(b'include/scsi/api.h', (self.output() / entry['artifact']).read_bytes())
        original = next((self.output() / 'review').glob('*-upstream.patch'))
        self.assertIn(b'external dependency', original.read_bytes())

    def test_diff_maps_makefile_and_classifies_committed_tree_only(self):
        self.commit(self.linux, 'scsi: qla2xxx: Add', {qla2xxx.UPSTREAM + 'new.c': 'new\n'})
        (self.scst / (qla2xxx.DEST + 'qla.c')).write_text('uncommitted\n')
        report = json.loads(self.invoke('diff', '--json')[0])
        statuses = {e['path']: e['status'] for e in report['files']}
        self.assertEqual(statuses[qla2xxx.DEST + 'Makefile_in-tree'], 'identical')
        self.assertEqual(statuses[qla2xxx.DEST + 'Makefile'], 'scst-only')
        self.assertEqual(statuses[qla2xxx.DEST + 'qla.c'], 'identical')
        self.assertEqual(statuses[qla2xxx.DEST + 'new.c'], 'linux-only')
        limited = json.loads(self.invoke('diff', '--json', '--path', 'new.c')[0])
        self.assertEqual(len(limited['files']), 1)
        output = self.invoke('diff', '--patch', '--path', 'new.c')[0]
        self.assertIn('-new\n', output)
        self.invoke('diff', '--path', '../escape', ok=False)
        self.invoke('diff', '--path', 'not-present.c', ok=False)

    def test_decisions_require_reason_and_reachable_resolution(self):
        oid = self.commit(self.linux, 'scsi: qla2xxx: Optional change',
                          {qla2xxx.UPSTREAM + 'qla.c': 'new\n'})
        path = self.root / 'decisions.json'
        document = {'version': 1, 'decisions': {oid: {'status': 'skip', 'reason': 'Not applicable'}}}
        path.write_text(json.dumps(document))
        report = self.export('--decisions', path)
        self.assertEqual(report['counts'], {'skip': 1})
        self.assertEqual(report['patch_count'], 0)
        document['decisions'][oid] = {'status': 'resolved', 'reason': 'Adapted separately',
                                       'scst_commit': self.scst_base}
        path.write_text(json.dumps(document))
        self.assertEqual(self.history('--decisions', path)['counts'], {'resolved': 1})
        document['decisions'][oid]['reason'] = ''
        path.write_text(json.dumps(document))
        self.invoke('history', '--decisions', path, ok=False)
        unmerged = self.commit(self.scst, 'Unmerged adaptation',
                               {qla2xxx.DEST + 'qla.c': 'unmerged\n'})
        self.git(self.scst, 'checkout', '-q', self.scst_base)
        document['decisions'][oid].update(reason='Unmerged', scst_commit=unmerged)
        path.write_text(json.dumps(document))
        self.invoke('history', '--decisions', path, ok=False)

    def test_reverted_import_is_not_silently_skipped(self):
        oid = self.commit(self.linux, 'scsi: qla2xxx: Fix', {qla2xxx.UPSTREAM + 'qla.c': 'fix\n'})
        self.commit(self.scst, f'qla2x00t-32gbit: Fix\n\n[ commit {oid} upstream ]',
                    {qla2xxx.DEST + 'qla.c': 'fix\n'})
        self.git(self.scst, 'revert', '--no-edit', 'HEAD')
        self.invoke('history', ok=False)
        report = self.export('--since', self.base)
        self.assertEqual(report['commits'][0]['status'], 'review')
        self.assertEqual(report['patch_count'], 0)
        self.assertTrue((self.output() / report['commits'][0]['artifact']).is_file())

    def test_output_is_never_replaced_even_when_empty_or_symlink(self):
        self.output().mkdir()
        self.invoke('export', '--output', self.output(), ok=False)
        (self.output() / 'keep').write_text('previous run')
        self.invoke('export', '--output', self.output(), ok=False)
        self.assertEqual((self.output() / 'keep').read_text(), 'previous run')
        link = self.root / 'broken-link'
        link.symlink_to(self.root / 'missing')
        self.invoke('export', '--output', link, ok=False)
        self.assertTrue(link.is_symlink())

    def test_empty_range_is_distinct_from_invalid_ref(self):
        self.assertEqual(self.history()['commits'], [])
        self.invoke('history', '--to', 'not-a-ref', ok=False)
        self.invoke('history', '--since', 'not-a-ref', ok=False)
        self.git(self.linux, 'checkout', '-q', '--orphan', 'unrelated')
        self.commit(self.linux, 'Unrelated root', {qla2xxx.UPSTREAM + 'qla.c': 'other\n'})
        self.invoke('history', '--since', self.base, ok=False)

    def test_unresolved_latest_marker_requires_explicit_base(self):
        self.commit(self.scst, 'qla2x00t-32gbit: Missing source\n\n'
                    '[ commit 0000000000000000000000000000000000000001 upstream ]',
                    {qla2xxx.DEST + 'qla.c': 'missing\n'})
        self.invoke('history', ok=False)
        report = self.history('--since', self.base)
        self.assertEqual(len(report['unresolved_markers']), 1)

    def test_shallow_history_is_rejected(self):
        clone = self.root / 'shallow'
        self.git(self.root, 'clone', '-q', '--depth=1', self.linux.as_uri(), str(clone))
        self.invoke('history', '--linux', clone, ok=False)

    def test_partial_clone_is_rejected_without_attempting_network_access(self):
        self.git(self.linux, 'config', 'remote.origin.promisor', 'true')
        _, error = self.invoke('history', ok=False)
        self.assertIn('partial clone', error)

    def test_latest_import_with_multiple_markers_needs_an_explicit_base(self):
        oid = self.commit(self.linux, 'scsi: qla2xxx: Fix', {qla2xxx.UPSTREAM + 'qla.c': 'fix\n'})
        self.commit(self.scst, 'qla2x00t-32gbit: Combined import\n\n'
                    f'[ commit {self.base} upstream ]\n[ commit {oid} upstream ]',
                    {qla2xxx.DEST + 'qla.c': 'fix\n'})
        self.invoke('history', ok=False)
        self.assertEqual(self.history('--since', self.base)['counts'], {'recorded': 1})

    def test_mode_and_missing_final_newline_survive_export(self):
        self.commit(self.linux, 'scsi: qla2xxx: No final newline',
                    {qla2xxx.UPSTREAM + 'qla.c': 'no newline'})
        path = self.linux / (qla2xxx.UPSTREAM + 'qla.c')
        path.chmod(0o755)
        self.commit(self.linux, 'scsi: qla2xxx: Change mode', {})
        self.export()
        for filename in (self.output() / 'series').read_text().splitlines():
            self.git(self.scst, 'am', str(self.output() / filename))
        path = self.scst / (qla2xxx.DEST + 'qla.c')
        self.assertEqual(path.read_bytes(), b'no newline')
        self.assertTrue(path.stat().st_mode & 0o111)

    def test_failure_does_not_publish_incomplete_bundle(self):
        self.commit(self.linux, 'scsi: qla2xxx: Fix', {qla2xxx.UPSTREAM + 'qla.c': 'new\n'})
        with patch.object(qla2xxx, 'import_patch', side_effect=qla2xxx.ToolError('test failure')):
            self.invoke('export', '--output', self.output(), ok=False)
        self.assertFalse(self.output().exists())
        self.assertFalse(list(self.root.glob('.qla2xxx-*')))

    def test_export_can_run_from_an_unrelated_directory(self):
        result = subprocess.run([
            sys.executable, str(Path(qla2xxx.__file__).resolve()), 'export',
            '--linux', str(self.linux), '--scst', str(self.scst), '--to', 'HEAD',
            '--output', str(self.output()), '--json'], cwd=self.root, env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout)['patch_count'], 0)

    def test_audit_keeps_raw_diff_literals_behavior_and_blame(self):
        self.commit(self.linux, 'Base source', {qla2xxx.UPSTREAM + 'qla.c':
                    'int mode = 1;\nchar *name = "a b";\n'})
        change = self.commit(self.scst, 'Change policy', {qla2xxx.DEST + 'qla.c':
                             'int mode = 0;\nchar *name = "ab";\n'})
        report = json.loads(self.invoke('audit', '--blame', '--json', '--path', 'qla.c')[0])
        entry = report['files'][0]
        self.assertEqual(entry['assessment'], 'residual-review')
        self.assertIn('-int mode = 1;', entry['raw_diff'])
        self.assertIn('+int mode = 0;', entry['raw_diff'])
        self.assertGreater(entry['residual_tokens']['added'], 0)
        self.assertTrue(all(h['requires_review'] for h in entry['hunks']))
        self.assertIn(change, {c['commit'] for h in entry['hunks'] for c in h['scst_last_editors']})
        self.assertEqual(self.git(self.scst, 'status', '--porcelain').stdout, b'')

    def test_audit_distinguishes_comment_noise_from_profile_equality(self):
        self.commit(self.linux, 'Base source', {qla2xxx.UPSTREAM + 'qla.c': 'int f(void) { return 1; }\n'})
        self.commit(self.scst, 'Reformat', {qla2xxx.DEST + 'qla.c':
                    '/* comment */\nint f(void)\n{\n\treturn 1; // explanation\n}\n'})
        entry = json.loads(self.invoke('audit', '--json', '--path', 'qla.c')[0])['files'][0]
        self.assertEqual(entry['assessment'], 'lexical-only')
        self.assertEqual(entry['hunks'], [])
        self.commit(self.scst, 'Backport', {qla2xxx.DEST + 'qla.c':
                    '#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0)\n'
                    'int f(void) { return 1; }\n#else\nint f(void) { return 2; }\n#endif\n'})
        entry = json.loads(self.invoke('audit', '--json', '--kernel-version', '7.3',
                                       '--path', 'qla.c')[0])['files'][0]
        self.assertEqual(entry['assessment'], 'equal-under-profile')
        self.assertIn('return 2;', entry['raw_diff'])
        entry = json.loads(self.invoke('audit', '--json', '--kernel-version', '6.1',
                                       '--path', 'qla.c')[0])['files'][0]
        self.assertEqual(entry['assessment'], 'residual-review')
        self.assertEqual(entry['hunks'][0]['scst']['start'], 4)

    def test_audit_preserves_unknown_vendor_and_config_branches(self):
        self.commit(self.linux, 'Base source', {qla2xxx.UPSTREAM + 'qla.c': 'int value;\n'})
        self.commit(self.scst, 'Conditional', {qla2xxx.DEST + 'qla.c':
                    '#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0) && defined(VENDOR)\n'
                    'int other;\n#else\nint value;\n#endif\n'})
        entry = json.loads(self.invoke('audit', '--json', '--kernel-version', '7.3',
                                       '--path', 'qla.c')[0])['files'][0]
        self.assertEqual(entry['assessment'], 'residual-review')
        self.assertEqual(entry['scst_conditions'][0]['result'], 'unknown')
        entry = json.loads(self.invoke('audit', '--json', '--kernel-version', '7.3',
                                       '--undef', 'VENDOR', '--path', 'qla.c')[0])['files'][0]
        self.assertEqual(entry['assessment'], 'equal-under-profile')

    def test_audit_rejects_conflicting_profiles_and_excludes_worktree(self):
        self.invoke('audit', '--kernel-version', '7.3', '--define', 'LINUX_VERSION_CODE=1', ok=False)
        self.invoke('audit', '--define', 'VENDOR=1', '--undef', 'VENDOR', ok=False)
        self.invoke('audit', '--kernel-version', 'v7.3', ok=False)
        with self.assertRaises(SystemExit):
            self.invoke('audit', '--json', '--patch')
        (self.scst / (qla2xxx.DEST + 'qla.c')).write_text('uncommitted\n')
        entry = json.loads(self.invoke('audit', '--json', '--path', 'qla.c')[0])['files'][0]
        self.assertEqual(entry['assessment'], 'identical')

    def test_audit_never_hides_modes_binary_or_non_c_files(self):
        self.commit(self.scst, 'Add binary and documentation', {
            qla2xxx.DEST + 'binary.h': b'\0\xff', qla2xxx.DEST + 'README': 'SCST\n',
            qla2xxx.DEST + 'invalid.c': b'\xff'})
        (self.scst / (qla2xxx.DEST + 'qla.c')).chmod(0o755)
        self.commit(self.scst, 'Mode', {})
        entries = {e['path'][len(qla2xxx.DEST):]: e for e in
                   json.loads(self.invoke('audit', '--json')[0])['files']}
        self.assertEqual(entries['qla.c']['assessment'], 'mode-review')
        self.assertEqual(entries['binary.h']['assessment'], 'binary-review')
        self.assertEqual(entries['invalid.c']['assessment'], 'encoding-review')
        self.assertEqual(entries['README']['assessment'], 'non-c-review')


class ProjectionTests(unittest.TestCase):
    def project(self, source, *definitions):
        return audit.project(audit.source_lines(source), audit.profile('7.3', list(definitions), []))

    def test_strings_macro_spacing_and_token_boundaries_survive(self):
        def value(source):
            return [text for text, _ in audit.tokens(audit.source_lines(source))]
        self.assertEqual(value('char *s = "/* a b */"; // outside\n'),
                         value('char*s="/* a b */"; /* outside */\n'))
        self.assertNotEqual(value('char *s="/* a b */";'), value('char *s="/* ab */";'))
        self.assertNotEqual(value('x + +y;'), value('x ++ y;'))
        self.assertNotEqual(value('#define F(x) x\n'), value('#define F (x) x\n'))
        self.assertEqual(value('double n = 1e+3;'), ['double', 'n', '=', '1e+3', ';'])

    def test_splicing_precedes_line_comments_and_preserves_line_numbers(self):
        source = '// ignored \\\n#if 0\nint value;\n'
        projected, _, _ = self.project(source)
        self.assertEqual(audit.tokens(projected), [('int', 3), ('value', 3), (';', 3)])
        self.assertEqual(audit.tokens(audit.source_lines('\\\nint x;\n'))[0], ('int', 1))
        self.assertIn('\\ No newline at end of file\n+new\n', audit.unified('old', 'new', 'qla.c'))

    def test_unknown_outer_condition_keeps_decidable_nested_content(self):
        source = ('#ifndef HEADER\n#define HEADER\n'
                  '#if LINUX_VERSION_CODE > KERNEL_VERSION(6, 0, 0)\nnew_api();\n'
                  '#else\nold_api();\n#endif\n#endif\n')
        output, decisions, _ = self.project(source)
        text = ''.join(line for line, _ in output)
        self.assertIn('#ifndef HEADER', text)
        self.assertIn('new_api();', text)
        self.assertNotIn('old_api();', text)
        self.assertEqual([d['result'] for d in decisions], ['unknown', 'selected'])

    def test_local_redefinition_invalidates_external_facts(self):
        output, decisions, invalid = self.project('#define VENDOR 0\n#if VENDOR\na();\n'
                                                  '#else\nb();\n#endif\n', 'VENDOR=1')
        self.assertEqual(invalid, ['VENDOR'])
        self.assertEqual(decisions[0]['result'], 'unknown')
        self.assertIn('b();', ''.join(line for line, _ in output))

    def test_elif_and_short_circuit_do_not_discard_uncertainty(self):
        cases = [('#if 0\na();\n#elif 1\nb();\n#else\nc();\n#endif\n', 'b();'),
                 ('#if 0 && UNKNOWN(x)\na();\n#else\nb();\n#endif\n', 'b();'),
                 ('#if UNKNOWN\na();\n#elif 1\nb();\n#endif\n', '#if UNKNOWN')]
        for source, expected in cases:
            with self.subTest(source=source):
                output, _, _ = self.project(source)
                self.assertIn(expected, ''.join(line for line, _ in output))
        for expr in ('UNKNOWN + 2', '1U < -1', '2147483647 + 1', '0xffffffffffffffff',
                     '__import__("os")', '1 << 10', 'KERNEL_VERSION(7, 3, 300)'):
            self.assertIsNone(audit.Condition(expr, {}, True).value(), expr)

    def test_bad_nesting_is_an_error_not_an_empty_success(self):
        for source in ('#endif\n', '#if 1\nvalue\n', '#if 0\n#else\n#else\n#endif\n'):
            with self.assertRaises(ValueError):
                self.project(source)

    def test_api_changes_remain_review_candidates(self):
        self.assertEqual(audit.classify('timer_shutdown(&t);', 'timer_delete(&t);',
                                        'qla_edif.c')[0], 'behavior-candidate')
        self.assertEqual(audit.classify('struct bsg_job *job;', 'BSG_JOB_TYPE *job;',
                                        'qla_bsg.c')[0], 'compatibility-candidate')
        self.assertEqual(audit.scope_hint(audit.source_lines(
            'static int f(void)\n{\nreturn 1;\n}\n'), 3), 'f')

if __name__ == '__main__':
    unittest.main()
