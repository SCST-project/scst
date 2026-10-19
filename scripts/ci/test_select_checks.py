# SPDX-License-Identifier: GPL-2.0-only
"""Exercise PR selection with real Git histories; no VM or SCST access."""

from copy import deepcopy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import select_checks


class PathPolicyTests(unittest.TestCase):
    def setUp(self):
        self.config = select_checks.load_config()

    def test_known_guides_and_independent_tools_skip_all_builds(self):
        paths = ('README.md', 'README.clang', 'tests/ginkgo/README.md',
                 'scst/AGENTS.md', 'doc/CI.md', 'doc/KUNIT.md',
                 'CONTRIBUTING.md', 'INSTALL.md', 'scripts/README.md',
                 'scripts/checkpatch', 'scripts/checkpatch_commits',
                 'scripts/checkpatch_diff', 'scripts/checkpatch_scan',
                 'scripts/source/list-double-blank-lines',
                 'scripts/source/run-shellcheck')
        for check in select_checks.CHECKS:
            for path in paths:
                with self.subTest(check=check, path=path):
                    self.assertTrue(select_checks.can_skip(check, path, self.config))

    def test_shared_build_inputs_and_unknown_paths_run_all_checks(self):
        paths = ('scst/src/scst_lib.c', 'iscsi-scst/kernel/iscsi.c',
                 'scst_local/scst_local.c', 'usr/fileio/fileio.c',
                 'scstadmin/scstadmin', 'scst/src/kunit/select.mk',
                 'Makefile', 'scst/Makefile', 'doc/Makefile', '.dockerignore',
                 '.github/kernel-matrix.conf', '.github/ci-checks.toml',
                 'scripts/kernel/kernel-matrix',
                 'scripts/kernel/sign-modules', 'scripts/source/list-source-files',
                 'scripts/source/clean-source-tree', 'scripts/ci/select_checks.py',
                 f'scripts/ci/{Path(__file__).name}', 'scripts/ci/new-helper.py',
                 'scripts/checkpatch_new', 'scripts/source/new-helper',
                 'doc/new-helper.py', 'scst/README.c', 'new-component/config.json')
        for check in select_checks.CHECKS:
            for path in paths:
                with self.subTest(check=check, path=path):
                    self.assertFalse(select_checks.can_skip(check, path, self.config))

    def test_known_inputs_select_their_consumers(self):
        cases = {
            'tests/ginkgo/suite/suite_test.go': {'ginkgo'},
            'tests/ginkgo/internal/testrun/labels.json': {'ginkgo'},
            'scripts/kunit/run.py': {'ginkgo', 'kunit'},
            'scripts/kunit/inventory.py': {'ginkgo', 'kunit'},
            'scripts/ci/kernel.env': {'ginkgo', 'kunit'},
            'scripts/ci/vm.py': {'ginkgo', 'kunit'},
            'scripts/ci/build-guest': {'ginkgo', 'kunit'},
            'scripts/kernel/generate-kernel-patch': {'kunit', 'regression'},
            'scripts/kernel/run-regression-tests': {'kunit', 'regression'},
            'debian/rules': {'clang'},
            'scripts/release/build-rpm-artifacts': set(),
            'scripts/release/generate-release-archive': set(),
            'scripts/release/prepare-package-release': set(),
            'scripts/release/update-version': set(),
            '.github/workflows/ci.yml': {'clang'},
            '.github/workflows/rpm.yml': set(),
            '.github/workflows/kunit.yml': {'kunit'},
            '.github/workflows/ginkgo.yml': {'ginkgo'},
            '.github/workflows/run_regression_tests.yaml': {'regression'},
            'doc/scst_pg.sgml': {'kunit', 'clang', 'regression'},
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual({check for check in select_checks.CHECKS
                                  if not select_checks.can_skip(check, path, self.config)}, expected)

    def test_packaged_and_kernel_exported_documentation_is_not_a_blanket_exemption(self):
        paths = ('scstadmin/scstadmin.sysfs/scst-1.0.0/README',
                 'iscsi-scst/doc/manpages/iscsi-scstd.8',
                 'fcst/README', 'scst/README_in-tree')
        for check in select_checks.CHECKS:
            for path in paths:
                with self.subTest(check=check, path=path):
                    self.assertFalse(select_checks.can_skip(check, path, self.config))

    def test_push_and_manual_runs_do_not_consult_paths(self):
        with patch('select_checks.changed_paths') as changed:
            for check in select_checks.CHECKS:
                for event in ('push', 'workflow_dispatch'):
                    self.assertTrue(select_checks.select_run(check, event, '', '', self.config)[0])
            changed.assert_not_called()


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.config = {'skip': {'paths': [], 'basenames': []}, 'rules': []}

    def test_unknown_or_missing_fields_are_rejected(self):
        cases = [
            {}, {'skip': self.config['skip']},
            dict(self.config, typo=[]), dict(self.config, skip=[]),
            dict(self.config, skip={'paths': []}),
            dict(self.config, skip={'paths': [], 'basenames': [], 'typo': []}),
            dict(self.config, rules={}), dict(self.config, rules=[[]]),
        ]
        for config in cases:
            with self.subTest(config=config), self.assertRaises(ValueError):
                select_checks.validate_config(config)
        for rule in ({'paths': ['doc/file']},
                     {'paths': ['doc/file'], 'checks': ['ginkgo'], 'typo': []},
                     {'paths': ['doc/file'], 'prefixes': ['doc/'], 'checks': ['ginkgo']}):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                select_checks.validate_config(dict(self.config, rules=[rule]))

    def test_check_names_and_types_are_validated(self):
        for checks in ([], ['unknown'], ['ginkgo', 'ginkgo'], 'ginkgo', [True], [1], ['']):
            self.config['rules'] = [{'paths': ['file'], 'checks': checks}]
            with self.subTest(checks=checks), self.assertRaisesRegex(ValueError, 'checks'):
                select_checks.validate_config(self.config)

    def test_selectors_must_be_literal_relative_paths(self):
        bad = ['', '/absolute', '../outside', './relative', 'a/../b', 'a//b',
               'a\\b', 'a\nb', 'a\rb', 'a\0b', 'a*', 'a?', 'a[bc]', 'a ', ' a']
        for kind in ('paths', 'prefixes'):
            values = bad + (['trailing/'] if kind == 'paths' else ['missing-slash'])
            for value in values:
                self.config['rules'] = [{kind: [value], 'checks': ['ginkgo']}]
                with self.subTest(kind=kind, value=value), self.assertRaises(ValueError):
                    select_checks.validate_config(self.config)
            for values in ([], 'file', [False], ['file/', 'file/']):
                self.config['rules'] = [{kind: values, 'checks': ['ginkgo']}]
                with self.subTest(kind=kind, values=values), self.assertRaises(ValueError):
                    select_checks.validate_config(self.config)
        self.config['rules'] = []
        for values in (['doc/README'], ['.'], ['..'], ['*'], [''], ['AGENTS.md', 'AGENTS.md']):
            self.config['skip']['basenames'] = values
            with self.subTest(basenames=values), self.assertRaises(ValueError):
                select_checks.validate_config(self.config)

    def test_duplicate_paths_and_overlapping_prefixes_are_rejected(self):
        for kind, first, second in (('paths', 'file', 'file'),
                                    ('prefixes', 'scripts/', 'scripts/'),
                                    ('prefixes', 'scripts/', 'scripts/kunit/'),
                                    ('prefixes', 'scripts/kunit/', 'scripts/')):
            self.config['rules'] = [{kind: [first], 'checks': ['ginkgo']},
                                    {kind: [second], 'checks': ['kunit']}]
            with self.subTest(kind=kind, first=first), self.assertRaises(ValueError):
                select_checks.validate_config(self.config)
        self.config['skip']['paths'] = ['file']
        self.config['rules'] = [{'paths': ['file'], 'checks': ['ginkgo']}]
        with self.assertRaisesRegex(ValueError, 'duplicate path'):
            select_checks.validate_config(self.config)

    def test_exact_paths_override_prefixes_regardless_of_rule_order(self):
        rules = [{'prefixes': ['tests/'], 'checks': ['ginkgo']},
                 {'paths': ['tests/tool.py'], 'checks': ['kunit']}]
        for ordered in (rules, list(reversed(rules))):
            self.config['rules'] = ordered
            select_checks.validate_config(self.config)
            self.assertTrue(select_checks.can_skip('ginkgo', 'tests/tool.py', self.config))
            self.assertFalse(select_checks.can_skip('kunit', 'tests/tool.py', self.config))
            self.assertFalse(select_checks.can_skip('ginkgo', 'tests/new.py', self.config))
            self.assertFalse(select_checks.can_skip('ginkgo', 'tests-other/new.py', self.config))
        self.config['skip'] = {'paths': ['tests/tool.py'], 'basenames': ['AGENTS.md']}
        self.config['rules'] = rules[:1]
        select_checks.validate_config(self.config)
        for path in ('tests/tool.py', 'tests/AGENTS.md'):
            self.assertTrue(select_checks.can_skip('ginkgo', path, self.config))

    def test_control_files_cannot_be_exempted_by_config(self):
        for path in select_checks.CONTROL_PATHS:
            for kind in ('skip', 'paths', 'prefixes'):
                config = deepcopy(self.config)
                if kind == 'skip':
                    config['skip']['paths'] = [path]
                else:
                    value = path if kind == 'paths' else path.rsplit('/', 1)[0] + '/'
                    config['rules'] = [{kind: [value], 'checks': ['ginkgo']}]
                select_checks.validate_config(config)
                for check in select_checks.CHECKS:
                    with self.subTest(path=path, kind=kind, check=check):
                        self.assertFalse(select_checks.can_skip(check, path, config))


class ConfigCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.script = self.root / 'repo/scripts/ci/select_checks.py'
        self.script.parent.mkdir(parents=True)
        self.script.write_text(Path(select_checks.__file__).read_text())
        self.config = self.root / 'repo/.github/ci-checks.toml'
        self.config.parent.mkdir(parents=True)
        self.config.write_text(select_checks.CONFIG_PATH.read_text())
        self.output = self.root / 'output'
        self.summary = self.root / 'summary'

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(self.script), *args], cwd=self.root,
                              env=dict(os.environ, GITHUB_OUTPUT=str(self.output),
                                       GITHUB_STEP_SUMMARY=str(self.summary)),
                              capture_output=True, text=True, check=False)

    def test_validation_resolves_config_from_script_and_emits_no_selection(self):
        result = self.run_cli('--validate-config')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('config is valid', result.stdout)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.summary.exists())

    def test_invalid_or_missing_config_fails_before_selection_for_every_event(self):
        for content in (None, '[broken', 'skip = {}\nrules = []',
                        '[skip]\npaths = []\nbasenames = []\n'
                        '[[rules]]\npaths = ["file"]\nchecks = ["typo"]'):
            if content is None:
                self.config.unlink()
            else:
                self.config.write_text(content)
            cases = [('--validate-config',)] + [
                ('--check', 'ginkgo', '--event', event)
                for event in ('pull_request', 'push', 'workflow_dispatch')]
            for args in cases:
                with self.subTest(content=content, args=args):
                    result = self.run_cli(*args)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Cannot determine CI selection:', result.stderr)
                    self.assertNotIn('Traceback', result.stderr)
                    self.assertFalse(self.output.exists())
                    self.assertFalse(self.summary.exists())

    def test_selection_still_requires_check_and_event(self):
        for args in ((), ('--check', 'ginkgo'), ('--event', 'push')):
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.output.exists())


class GitSelectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.output = self.root / 'output'
        self.summary = self.root / 'summary'
        self.git('init', '-q', '--initial-branch=main')
        self.write('scst/core.c', 'core\n')
        self.write('doc/CI.md', 'documentation\n')
        self.base = self.commit()

    def git(self, *args):
        return subprocess.check_output([
            'git', '-c', 'user.name=CI test', '-c', 'user.email=ci@example.invalid',
            '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', *args,
        ], cwd=self.repo, text=True).strip()

    def write(self, name, text):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self):
        self.git('add', '-A')
        self.git('commit', '-qm', 'Test change')
        return self.git('rev-parse', 'HEAD')

    def select(self, *, check='ginkgo', base=None, head='HEAD', event='pull_request'):
        self.output.unlink(missing_ok=True)
        self.summary.unlink(missing_ok=True)
        return subprocess.run([
            sys.executable, str(Path(select_checks.__file__).resolve()),
            '--check', check, '--event', event,
            '--base', self.base if base is None else base,
            '--head', head,
        ], cwd=self.repo, env=dict(os.environ, GITHUB_OUTPUT=str(self.output),
                                  GITHUB_STEP_SUMMARY=str(self.summary)),
            capture_output=True, text=True, check=False)

    def assert_selection(self, expected, **kwargs):
        result = self.select(**kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text(), f'run={str(expected).lower()}\n')
        self.assertIn(kwargs.get('check', 'ginkgo') + ':', self.summary.read_text())

    def test_docs_and_checkpatch_only(self):
        self.write('doc/CI.md', 'updated documentation\n')
        self.write('scripts/checkpatch', '#!/bin/bash\n')
        self.commit()
        for check in select_checks.CHECKS:
            with self.subTest(check=check):
                self.assert_selection(False, check=check)

    def test_earlier_code_change_is_not_hidden_by_latest_docs_commit(self):
        self.write('scst/core.c', 'changed core\n')
        self.commit()
        self.write('doc/CI.md', 'updated documentation\n')
        self.commit()
        self.assert_selection(True)

    def test_kunit_tooling_change_is_not_exempted_with_documentation(self):
        self.write('doc/CI.md', 'updated documentation\n')
        self.write('scripts/kunit/run.py', '# changed KUnit runner\n')
        self.commit()
        self.assert_selection(True)

    def test_changes_on_base_branch_are_excluded_from_pr_diff(self):
        self.git('checkout', '-qb', 'topic')
        self.write('doc/CI.md', 'updated documentation\n')
        head = self.commit()
        self.git('checkout', '-q', 'main')
        self.write('scst/core.c', 'upstream core change\n')
        base = self.commit()
        self.assert_selection(False, base=base, head=head)

    def test_source_renamed_to_documentation_still_requires_checks(self):
        self.git('mv', 'scst/core.c', 'doc/core.md')
        self.commit()
        self.assert_selection(True)

    def test_documentation_renamed_to_source_requires_checks(self):
        self.git('mv', 'doc/CI.md', 'scst/new.c')
        self.commit()
        self.assert_selection(True)

    def test_documentation_rename_can_skip(self):
        self.git('mv', 'doc/CI.md', 'doc/KUNIT.md')
        self.commit()
        self.assert_selection(False)

    def test_deletions_are_classified(self):
        self.git('rm', '-q', 'doc/CI.md')
        self.commit()
        self.assert_selection(False)
        self.git('rm', '-q', 'scst/core.c')
        self.commit()
        self.assert_selection(True)

    def test_changed_file_list_is_not_truncated(self):
        for index in range(350):
            self.write(f'guides/{index}/AGENTS.md', 'instructions\n')
        self.write('scst/core.c', 'changed core\n')
        self.commit()
        self.assert_selection(True)

    def test_paths_with_newlines_are_not_split_into_exempt_names(self):
        self.write('doc/CI.md\nREADME.md', 'unknown input\n')
        self.commit()
        self.assert_selection(True)

    def test_empty_diff_runs_conservatively(self):
        for check in select_checks.CHECKS:
            self.assert_selection(True, check=check)

    def test_config_change_runs_every_check(self):
        self.write('.github/ci-checks.toml', select_checks.CONFIG_PATH.read_text())
        self.commit()
        for check in select_checks.CHECKS:
            self.assert_selection(True, check=check)

    def test_push_and_manual_events_run_even_for_docs_only(self):
        self.write('doc/CI.md', 'updated documentation\n')
        self.commit()
        for check in select_checks.CHECKS:
            for event in ('push', 'workflow_dispatch'):
                with self.subTest(check=check, event=event):
                    self.assert_selection(True, check=check, event=event, base='', head='')

    def test_debian_only_change_selects_only_clang(self):
        self.write('debian/rules', '# packaging change\n')
        self.commit()
        for check in select_checks.CHECKS:
            with self.subTest(check=check):
                self.assert_selection(check == 'clang', check=check)

    def test_release_only_change_skips_pr_checks_but_keeps_master_runs(self):
        self.write('.github/workflows/rpm.yml', '# master-only workflow\n')
        self.write('scripts/release/build-rpm-artifacts', '# RPM build\n')
        self.commit()
        for check in select_checks.CHECKS:
            with self.subTest(check=check):
                self.assert_selection(False, check=check)
                self.assert_selection(True, check=check, event='push', base='', head='')

    def test_cross_component_rename_requires_both_consumers(self):
        self.write('tests/ginkgo/example.go', '// test\n')
        self.base = self.commit()
        (self.repo / 'debian').mkdir()
        self.git('mv', 'tests/ginkgo/example.go', 'debian/example.go')
        self.commit()
        for check in select_checks.CHECKS:
            with self.subTest(check=check):
                self.assert_selection(check in ('ginkgo', 'clang'), check=check)

    def test_invalid_check_fails_without_skip_output(self):
        result = self.select(check='unknown')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())

    def test_missing_or_invalid_revisions_fail_without_skip_output(self):
        for base, head in (('', 'HEAD'), (self.base, ''),
                           ('missing-ref', 'HEAD'), (self.base, 'missing-ref')):
            with self.subTest(base=base, head=head):
                result = self.select(base=base, head=head)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Cannot determine CI selection', result.stderr)
                self.assertFalse(self.output.exists())
                self.assertFalse(self.summary.exists())

    def test_missing_merge_base_fails_without_skip_output(self):
        self.git('checkout', '-q', '--orphan', 'unrelated')
        self.write('doc/other.md', 'unrelated history\n')
        self.commit()
        result = self.select()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Cannot determine CI selection', result.stderr)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.summary.exists())


if __name__ == '__main__':
    unittest.main()
