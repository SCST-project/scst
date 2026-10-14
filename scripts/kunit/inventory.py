# SPDX-License-Identifier: GPL-2.0-only
"""List source suite registrations without a kernel build or module operations."""

import argparse
from pathlib import Path
import re

from labels import DEFAULT_LABEL_CONFIG, expand_labels, load_composites

REGISTRATION = re.compile(
    r'^scst_kunit_suite\(\s*\w+\s*,\s*"([A-Z][A-Z0-9_]*)"\s*,\s*'
    r'"((?:-[A-Za-z0-9_-]+)?)"\s*,', re.M)
COMMENTS = re.compile(r'("(?:\\.|[^"\\])*")|/\*.*?\*/|//[^\n]*', re.S)


def source_suites(paths):
    suites = {}
    for path in sorted(set(paths)):
        source = COMMENTS.sub(lambda match: match[1] or '', path.read_text())
        for label, suffix in REGISTRATION.findall(source):
            name = 'scst-' + label + suffix
            if label == 'ALL' or name in suites:
                raise ValueError(f'{path}: reserved label or duplicate suite {name}')
            suites[name] = label
    return suites


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directories', nargs='+', type=Path)
    parser.add_argument('--label-config', type=Path, default=DEFAULT_LABEL_CONFIG,
                        help='composite labels TOML (default: scripts/kunit/labels.toml)')
    args = parser.parse_args(argv)
    try:
        suites = source_suites(path for directory in args.directories
                               for path in directory.rglob('*.c'))
        if not suites:
            raise ValueError('No source suites found')
        composites = load_composites(args.label_config.expanduser())
        expanded = {name: expand_labels(suites, [name], composites) for name in composites}
        available = sorted(set(suites.values()) | composites.keys())
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print('Source suites (the runner validates the built modules):')
    print('Available KUNIT_LABEL: ' + ' '.join(available) + ' ALL')
    for name, label in sorted(suites.items()):
        print(f'  {label}: {name}')
    if composites:
        print('Composite labels:')
        for name in sorted(composites):
            print(f"  {name}: {composites[name]['description']}".rstrip())
            for suite in sorted(expanded[name]):
                print(f'    {suite}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
