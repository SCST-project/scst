#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Decide whether changed paths require a CI check; filter pull requests only."""

import argparse
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tomllib


CHECKS = ('ginkgo', 'kunit', 'clang', 'regression')
ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / '.github/ci-checks.toml'
CONTROL_PATHS = {CONFIG_PATH.relative_to(ROOT).as_posix(),
                 Path(__file__).resolve().relative_to(ROOT).as_posix()}


def string_list(value, name):
    if not isinstance(value, list) or any(not isinstance(item, str) or not item
                                          for item in value):
        raise ValueError(f'{name} must be an array of nonempty strings')
    if len(value) != len(set(value)):
        raise ValueError(f'{name} contains duplicate entries')
    return value


def validate_paths(values, kind, name):
    for value in string_list(values, name):
        path = value[:-1] if kind == 'prefixes' and value.endswith('/') else value
        if (not path or any(part in ('', '.', '..') for part in path.split('/'))
                or any(char in value for char in '\\*?[]\x00\r\n')
                or value != value.strip()
                or (kind == 'prefixes' and not value.endswith('/'))
                or (kind == 'basenames' and '/' in value)):
            raise ValueError(f'{name}: invalid literal {kind} entry {value!r}')


def validate_config(config):
    if set(config) != {'skip', 'rules'}:
        raise ValueError('Config must contain exactly skip and rules')
    skip = config['skip']
    if not isinstance(skip, dict) or set(skip) != {'paths', 'basenames'}:
        raise ValueError('skip must contain exactly paths and basenames')
    for kind, values in skip.items():
        validate_paths(values, kind, f'skip.{kind}')
    if not isinstance(config['rules'], list):
        raise ValueError('rules must be an array of tables')
    seen_paths = set(skip['paths'])
    seen_prefixes = set()
    for index, rule in enumerate(config['rules'], 1):
        name = f'rules[{index}]'
        if (not isinstance(rule, dict)
                or set(rule) not in ({'paths', 'checks'}, {'prefixes', 'checks'})):
            raise ValueError(f'{name} must contain checks and either paths or prefixes')
        checks = string_list(rule['checks'], f'{name}.checks')
        if not checks or set(checks) - set(CHECKS):
            raise ValueError(f'{name}.checks must select from {", ".join(CHECKS)}')
        kind = 'paths' if 'paths' in rule else 'prefixes'
        validate_paths(rule[kind], kind, f'{name}.{kind}')
        if not rule[kind]:
            raise ValueError(f'{name}.{kind} must not be empty')
        for value in rule[kind]:
            if kind == 'paths':
                if value in seen_paths:
                    raise ValueError(f'{name}: duplicate path {value!r}')
                seen_paths.add(value)
            else:
                if any(value.startswith(other) or other.startswith(value)
                       for other in seen_prefixes):
                    raise ValueError(f'{name}: overlapping prefix {value!r}')
                seen_prefixes.add(value)


def load_config(path=CONFIG_PATH):
    with path.open('rb') as stream:
        config = tomllib.load(stream)
    validate_config(config)
    return config


def can_skip(check, path, config):
    # Changes to the selection mechanism must exercise every check, regardless
    # of the policy being edited in the same PR.
    if path in CONTROL_PATHS:
        return False
    skip = config['skip']
    if PurePosixPath(path).name in skip['basenames'] or path in skip['paths']:
        return True
    for rule in config['rules']:
        if path in rule.get('paths', []):
            return check not in rule['checks']
    for rule in config['rules']:
        if any(path.startswith(prefix) for prefix in rule.get('prefixes', [])):
            return check not in rule['checks']
    # New code, shared build inputs and unclassified paths run every check.
    return False


def changed_paths(base, head):
    # Resolve refs before constructing a revision range; reject missing commits.
    commits = [subprocess.check_output(
        ['git', 'rev-parse', '--verify', '--end-of-options', f'{ref}^{{commit}}'],
        text=True).strip() for ref in (base, head)]
    output = subprocess.check_output([
        'git', 'diff', '--no-ext-diff', '--no-renames', '--name-only', '-z',
        f'{commits[0]}...{commits[1]}', '--',
    ])
    # No rename detection: both the deleted and added path must be skip-safe.
    return [os.fsdecode(path) for path in output.split(b'\0') if path]


def select_run(check, event, base, head, config):
    if event != 'pull_request':
        return True, f'{check}: required for push and manual runs.'
    if not base or not head:
        raise ValueError('Pull-request selection requires base and head commits')
    paths = changed_paths(base, head)
    if not paths:
        return True, f'{check}: required because the PR diff is empty.'
    for path in paths:
        print(f'Changed path: {path!r}')
    if any(not can_skip(check, path, config) for path in paths):
        return True, f'{check}: required by relevant or unclassified changes.'
    return False, f'{check}: skipped because all changed paths are known unrelated inputs.'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validate-config', action='store_true',
                        help='validate the CI path policy without selecting a check')
    parser.add_argument('--check', choices=CHECKS)
    parser.add_argument('--event',
                        choices=('pull_request', 'push', 'workflow_dispatch'))
    parser.add_argument('--base', default='')
    parser.add_argument('--head', default='')
    args = parser.parse_args()
    if not args.validate_config and (not args.check or not args.event):
        parser.error('--check and --event are required unless using --validate-config')
    try:
        config = load_config()
        if args.validate_config:
            print('CI path config is valid.')
            return 0
        required, reason = select_run(args.check, args.event, args.base, args.head, config)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f'Cannot determine CI selection: {error}', file=sys.stderr)
        return 1
    print(reason)
    result = f'run={str(required).lower()}\n'
    print(result, end='')
    if os.environ.get('GITHUB_OUTPUT'):
        with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:
            stream.write(result)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a') as stream:
            stream.write(reason + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
