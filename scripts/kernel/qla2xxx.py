#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Inspect Linux qla2xxx history, compare SCST, and export import candidates."""

import argparse
from collections import Counter
import difflib
from email.header import Header
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import qla2xxx_audit


ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = 'drivers/scsi/qla2xxx/'
TRACE = 'include/trace/events/qla.h'
DEST = 'qla2x00t-32gbit/'
PATHS = (UPSTREAM, TRACE)
MARKER = re.compile(r'^\[\s*commit ([0-9a-f]{7,40}) upstream\s*\]$', re.M)
REVERT = re.compile(r'^This reverts commit ([0-9a-f]{40})\.', re.M)


class ToolError(Exception):
    """An incomplete or invalid operation, never an empty successful result."""


class Repo:
    def __init__(self, path):
        self.path = Path(path).resolve()
        self.git('rev-parse', '--git-dir')
        if self.text('rev-parse', '--is-shallow-repository') == 'true':
            raise ToolError(f'{self.path}: complete history is required (shallow repository)')
        partial = self.run('config', '--get-regexp', r'^(extensions\.partialclone|remote\..*\.promisor)$')
        if partial.returncode not in (0, 1):
            raise ToolError(f'{self.path}: cannot inspect partial-clone configuration')
        for line in partial.stdout.decode('utf-8').splitlines():
            key, _, value = line.partition(' ')
            if key == 'extensions.partialclone' or value.lower() not in ('false', 'no', 'off', '0'):
                raise ToolError(f'{self.path}: complete objects are required (partial clone)')

    def run(self, *args, data=None):
        env = dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_NO_REPLACE_OBJECTS='1',
                   GIT_NO_LAZY_FETCH='1', LC_ALL='C')
        return subprocess.run(
            ['git', '--no-pager', '-C', str(self.path), *args], input=data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)

    def git(self, *args, data=None):
        result = self.run(*args, data=data)
        if result.returncode:
            error = result.stderr.decode('utf-8', errors='replace').strip()
            raise ToolError(f'{self.path}: git {args[0]} failed: {error}')
        return result.stdout

    def text(self, *args):
        return self.git(*args).decode('utf-8').strip()

    def resolve(self, ref):
        return self.text('rev-parse', '--verify', '--end-of-options', f'{ref}^{{commit}}')

    def ancestor(self, base, head):
        result = self.run('merge-base', '--is-ancestor', base, head)
        if result.returncode not in (0, 1):
            raise ToolError(f'{self.path}: cannot check ancestry of {base} and {head}')
        return result.returncode == 0

    def files(self, ref, *paths):
        result = {}
        for record in self.git('ls-tree', '-rz', ref, '--', *paths).split(b'\0'):
            if not record:
                continue
            metadata, name = record.split(b'\t', 1)
            mode, kind, oid = metadata.decode('ascii').split()
            if kind != 'blob':
                raise ToolError(f'Unsupported tree entry: {os.fsdecode(name)} ({kind})')
            result[os.fsdecode(name)] = {'mode': mode, 'oid': oid}
        return result


def destination(path):
    if path == TRACE:
        return DEST + TRACE
    if path.startswith(UPSTREAM):
        relative = path[len(UPSTREAM):]
        return DEST + ('Makefile_in-tree' if relative == 'Makefile' else relative)
    return None


def read_imports(scst, head, linux):
    """Markers are provenance evidence, not proof that their effects remain."""
    records = scst.git('log', '--full-history', '--format=%H%x00%B%x00',
                       head, '--', DEST).decode('utf-8').split('\0')
    imports = []
    reverted = set()
    for offset in range(0, len(records) - 2, 2):
        commit, message = records[offset].strip(), records[offset + 1]
        reverted.update(REVERT.findall(message))
        for marker in MARKER.findall(message):
            imports.append((marker, commit))
    markers = list(dict.fromkeys(marker for marker, _ in imports))
    resolved = {}
    if markers:
        output = linux.git('cat-file', '--batch-check=%(objectname) %(objecttype)',
                           data=('\n'.join(markers) + '\n').encode('ascii'))
        for marker, line in zip(markers, output.decode('ascii').splitlines()):
            oid, kind = line.split()
            resolved[marker] = oid if kind == 'commit' else None
    mapping = {}
    unresolved = []
    for marker, commit in imports:
        oid = resolved[marker]
        if oid:
            mapping.setdefault(oid, []).append(commit)
        else:
            unresolved.append({'marker': marker, 'scst_commit': commit})
    latest_markers = {resolved[marker] for marker, commit in imports
                      if commit == imports[0][1]} if imports else set()
    latest = latest_markers.pop() if len(latest_markers) == 1 else None
    return mapping, reverted, unresolved, latest


def load_decisions(path, linux, scst, target, head):
    """Explicit exceptions are portable; applied commits come from Git history."""
    if path is None:
        return {}
    document = json.loads(path.read_text(encoding='utf-8'))
    if (not isinstance(document, dict) or set(document) != {'version', 'decisions'}
            or document['version'] != 1 or not isinstance(document['decisions'], dict)):
        raise ToolError('Decisions must contain version: 1 and a decisions object')
    result = {}
    for oid, decision in document['decisions'].items():
        if not re.fullmatch(r'[0-9a-f]{40}', oid) or linux.resolve(oid) != oid:
            raise ToolError(f'Decision requires a full upstream commit SHA: {oid!r}')
        if not isinstance(decision, dict):
            raise ToolError(f'{oid}: decision must be an object')
        status = decision.get('status')
        expected = {'status', 'reason'}
        if status == 'resolved':
            expected.add('scst_commit')
        if (status not in ('skip', 'resolved') or set(decision) != expected
                or not isinstance(decision.get('reason'), str)
                or not decision['reason'].strip()):
            raise ToolError(f'{oid}: use skip/resolved with a nonempty reason; '
                            'resolved also requires scst_commit')
        if status == 'resolved':
            commit = scst.resolve(decision['scst_commit'])
            if commit != decision['scst_commit'] or not scst.ancestor(commit, head):
                raise ToolError(f'{oid}: scst_commit must be a full SHA reachable from SCST ref')
        # A shared file may contain decisions for later releases. Validate them,
        # but only report decisions reachable from this target.
        if linux.ancestor(oid, target):
            result[oid] = decision
    return result


def merge_diff(linux, oid):
    return linux.git('show', '--format=', '--remerge-diff', '--no-color',
                     '--no-ext-diff', '--no-textconv', oid, '--', *PATHS)


def make_history(args, linux, scst, target, head):
    imports, reverted, unresolved, latest = read_imports(scst, head, linux)
    if args.since:
        base = linux.resolve(args.since)
        source = 'explicit'
    elif latest:
        if reverted.intersection(imports[latest]):
            raise ToolError('The latest recorded import has been reverted; '
                            'specify --since before that import to review it')
        base, source = latest, 'latest-marker'
    else:
        raise ToolError('Cannot infer a valid upstream base; specify --since')
    if not linux.ancestor(base, target):
        raise ToolError('--since (or the latest marker) is not an ancestor of --to')
    decisions = load_decisions(args.decisions, linux, scst, target, head)
    warnings = ['Markers record provenance, not code equivalence or complete earlier coverage.',
                'Only committed trees are inspected; working-tree changes are excluded.']
    if source == 'latest-marker':
        warnings.append('The inferred base is a starting point, not a verified import boundary; '
                        'use --since for an audited release boundary.')
    if unresolved:
        warnings.append(f'{len(unresolved)} historical upstream markers could not be resolved.')
    commits = linux.text('rev-list', '--full-history', '--simplify-merges',
                         '--reverse', '--topo-order',
                         f'{base}..{target}', '--', *PATHS).splitlines()
    entries = []
    for oid in commits:
        metadata = linux.git('show', '-s', '--format=%P%x00%s%x00%an <%ae>%x00%aI',
                             oid).decode('utf-8').rstrip('\n').split('\0')
        parents, subject, author, date = metadata
        parents = parents.split()
        # Compare every parent for merges, including files outside the mapped
        # paths. No rename detection: source and destination both stay visible.
        paths = set()
        for parent in parents:
            paths.update(os.fsdecode(p) for p in linux.git(
                'diff', '--no-renames', '--name-only', '-z', parent, oid, '--').split(b'\0') if p)
        entry = {'upstream': oid, 'parents': parents, 'subject': subject,
                 'author': author, 'author_date': date,
                 'kind': 'merge' if len(parents) > 1 else 'commit',
                 'paths': sorted(p for p in paths if destination(p)),
                 'outside_paths': sorted(p for p in paths if not destination(p)),
                 'scst_commits': imports.get(oid, []), 'status': 'pending', 'review': []}
        if imports.get(oid):
            entry['status'] = 'recorded'
            if reverted.intersection(imports[oid]):
                entry['status'] = 'review'
                entry['review'].append('A recorded SCST import has a later revert; inspect its effect.')
        if len(parents) > 1:
            if len(parents) == 2:
                entry['merge_resolution'] = bool(merge_diff(linux, oid))
                entry['review'].append('Inspect merge resolution.' if entry['merge_resolution']
                                       else 'Inspect merge; remerge diff is empty.')
            else:
                entry['merge_resolution'] = None
                entry['review'].append('Octopus merge requires manual inspection of all parents.')
        elif entry['outside_paths']:
            entry['review'].append('Changes outside mapped paths require dependency review.')
        if oid in decisions:
            decision = decisions[oid]
            entry['decision'] = decision
            if decision['status'] == 'resolved' and decision['scst_commit'] in reverted:
                raise ToolError(f'{oid}: resolution commit has been reverted; update the decision')
            entry['status'] = decision['status']
        entries.append(entry)
    return {'version': 1, 'linux_target': target, 'linux_base': base,
            'base_source': source, 'scst_head': head,
            'mapping': {UPSTREAM: DEST, UPSTREAM + 'Makefile': DEST + 'Makefile_in-tree',
                        TRACE: DEST + TRACE},
            'warnings': warnings, 'unresolved_markers': unresolved,
            'counts': dict(Counter(e['status'] for e in entries)), 'commits': entries}


def mapped_diff(linux, parent, oid):
    common = ('diff', '--no-ext-diff', '--no-textconv', '--no-color', '--no-renames',
              '--full-index', '--binary', '--diff-algorithm=myers', '--unified=3')
    driver = linux.git(*common, '--relative=' + UPSTREAM,
                       '--src-prefix=a/' + DEST, '--dst-prefix=b/' + DEST,
                       parent, oid, '--', UPSTREAM)
    # Only patch headers change; never rewrite source text or binary payloads.
    replacements = {
        f'diff --git a/{DEST}Makefile b/{DEST}Makefile\n'.encode():
            f'diff --git a/{DEST}Makefile_in-tree b/{DEST}Makefile_in-tree\n'.encode(),
        f'--- a/{DEST}Makefile\n'.encode(): f'--- a/{DEST}Makefile_in-tree\n'.encode(),
        f'+++ b/{DEST}Makefile\n'.encode(): f'+++ b/{DEST}Makefile_in-tree\n'.encode(),
    }
    lines = []
    in_header = False
    for line in driver.splitlines(keepends=True):
        if line.startswith(b'diff --git '):
            in_header = True
        elif line.startswith((b'@@ ', b'GIT binary patch')):
            in_header = False
        lines.append(replacements.get(line, line) if in_header else line)
    driver = b''.join(lines)
    trace = linux.git(*common, '--relative=include/trace/events/',
                      '--src-prefix=a/' + DEST + 'include/trace/events/',
                      '--dst-prefix=b/' + DEST + 'include/trace/events/',
                      parent, oid, '--', TRACE)
    return driver + trace


def import_patch(linux, entry):
    oid = entry['upstream']
    mail = linux.git('show', '-s', '--format=email', '--encoding=UTF-8', oid)
    headers, body = mail.split(b'\n\n', 1)
    subject = re.sub(r'^(?:scsi: )?qla2xxx: ', '', entry['subject'])
    subject = '[PATCH] qla2x00t-32gbit: ' + subject
    encoded = Header(subject, 'utf-8', header_name='Subject').encode(linesep='\n').encode('ascii')
    headers, count = re.subn(rb'^Subject: [^\n]*(?:\n[ \t][^\n]*)*',
                            lambda _: b'Subject: ' + encoded, headers, flags=re.M)
    if count != 1:
        raise ToolError(f'{oid}: cannot construct mail subject')
    diff = mapped_diff(linux, entry['parents'][0], oid)
    if not diff:
        raise ToolError(f'{oid}: selected commit has no mapped patch')
    return (headers + b'\n\n' + body.rstrip() +
            f'\n\n[ commit {oid} upstream ]\n\n---\n\n'.encode() + diff)


def export_history(report, linux, output):
    """Publish a complete new bundle; never clear or replace a previous run."""
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise ToolError(f'Output already exists: {output}; choose a new directory')
    if not output.parent.is_dir():
        raise ToolError(f'Output parent does not exist: {output.parent}')
    with tempfile.TemporaryDirectory(prefix='.qla2xxx-', dir=output.parent) as temporary:
        bundle = Path(temporary) / 'bundle'
        bundle.mkdir()
        (bundle / 'review').mkdir()
        series = []
        artifacts = {}

        def write(name, data):
            (bundle / name).write_bytes(data)
            artifacts[name] = hashlib.sha256(data).hexdigest()

        for number, entry in enumerate(report['commits'], 1):
            if entry['status'] in ('recorded', 'skip', 'resolved'):
                continue
            stem = f'{number:04d}-{entry["upstream"][:12]}'
            if entry['kind'] == 'merge':
                if len(entry['parents']) == 2:
                    name = f'review/{stem}-remerge.txt'
                    write(name, merge_diff(linux, entry['upstream']))
                    entry['artifact'] = name
                continue
            patch = import_patch(linux, entry)
            if entry['outside_paths'] or entry['status'] == 'review':
                name = f'review/{stem}-scst.patch'
                write(f'review/{stem}-upstream.patch', linux.git(
                    'format-patch', '-1', '--stdout', '--no-signature', '--full-index',
                    '--binary', '--no-ext-diff', '--no-textconv', entry['upstream']))
            else:
                name = f'{stem}.patch'
                series.append(name)
            write(name, patch)
            entry['artifact'] = name
        write('series', (''.join(name + '\n' for name in series)).encode())
        report['artifacts_sha256'] = artifacts
        report['patch_count'] = len(series)
        report['review_count'] = sum(bool(e['review']) for e in report['commits']
                                     if e['status'] not in ('recorded', 'skip', 'resolved'))
        (bundle / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        # mkdir reserves the destination without replacing even an empty directory
        # created by someone else. All content is prepared before publication.
        output.mkdir()
        for item in bundle.iterdir():
            item.rename(output / item.name)
    return report


def compare(linux, target, scst, head, paths):
    upstream = linux.files(target, *PATHS)
    local = scst.files(head, DEST)
    mapped = {destination(path): (path, metadata) for path, metadata in upstream.items()}
    if paths:
        selected = set()
        for path in paths:
            if path.startswith('/') or any(part in ('', '.', '..') for part in path.split('/')):
                raise ToolError('--path must be relative to qla2x00t-32gbit/')
            selected.add(DEST + path)
        unknown = selected - set(mapped) - set(local)
        if unknown:
            raise ToolError(f'Paths absent from both trees: {", ".join(sorted(unknown))}')
    else:
        selected = set(mapped) | set(local)
    entries = []
    for name in sorted(selected):
        origin, before = mapped.get(name, (None, None))
        after = local.get(name)
        if before is None:
            status = 'scst-only'
        elif after is None:
            status = 'linux-only'
        elif before == after:
            status = 'identical'
        else:
            status = 'different'
        entries.append({'path': name, 'upstream_path': origin, 'status': status,
                        'linux': before, 'scst': after})
    return {'version': 1, 'linux_target': target, 'scst_head': head,
            'counts': dict(Counter(e['status'] for e in entries)), 'files': entries}


def print_tree_patch(report, linux, scst):
    for entry in report['files']:
        if entry['status'] == 'identical':
            continue
        name = entry['path']
        before = linux.git('cat-file', 'blob', entry['linux']['oid']) if entry['linux'] else b''
        after = scst.git('cat-file', 'blob', entry['scst']['oid']) if entry['scst'] else b''
        print(f'diff {entry["status"]} {name}')
        print(f'mode {entry["linux"]["mode"] if entry["linux"] else "absent"} -> '
              f'{entry["scst"]["mode"] if entry["scst"] else "absent"}')
        if b'\0' in before or b'\0' in after:
            print('Binary contents differ')
            continue
        for line in difflib.unified_diff(
                before.decode('utf-8', errors='replace').splitlines(keepends=True),
                after.decode('utf-8', errors='replace').splitlines(keepends=True),
                fromfile='linux/' + (entry['upstream_path'] or name), tofile='scst/' + name):
            sys.stdout.write(line)
            if not line.endswith('\n'):
                print('\n\\ No newline at end of file')


def print_history(report):
    print(f'Linux: {report["linux_base"]}..{report["linux_target"]}')
    print(f'SCST:  {report["scst_head"]}')
    for warning in report['warnings']:
        print(f'Note: {warning}')
    for entry in report['commits']:
        review = ' [review]' if entry['review'] else ''
        print(f'{entry["status"]:8} {entry["upstream"][:12]} '
              f'{entry["kind"]:6}{review} {entry["subject"]}')
        if entry.get('decision'):
            print(f'         {entry["decision"]["reason"]}')
        for reason in entry['review']:
            print(f'         {reason}')
    print('Counts: ' + json.dumps(report['counts'], sort_keys=True))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('history', 'diff', 'audit', 'export'):
        command = commands.add_parser(name)
        command.add_argument('--linux', type=Path, required=True, help='local Linux Git repository')
        command.add_argument('--scst', type=Path, default=ROOT, help='SCST repository (default: script root)')
        command.add_argument('--to', required=True, help='Linux tag/commit, resolved once to a full SHA')
        command.add_argument('--scst-ref', default='HEAD', help='committed SCST snapshot (default: HEAD)')
        command.add_argument('--json', action='store_true', help='machine-readable output')
        if name in ('history', 'export'):
            command.add_argument('--since', help='exclusive upstream base; otherwise infer latest marker')
            command.add_argument('--decisions', type=Path, help='reviewed skip/resolved decisions JSON')
        if name == 'export':
            command.add_argument('--output', type=Path, required=True, help='new bundle directory')
        if name in ('diff', 'audit'):
            command.add_argument('--path', action='append', default=[], help='SCST driver-relative file; repeatable')
            command.add_argument('--patch', action='store_true', help='textual review diff, not an import patch')
        if name == 'audit':
            command.add_argument('--kernel-version', help='project known conditions for MAJOR.MINOR[.PATCH]')
            command.add_argument('--define', action='append', default=[], help='assume NAME=integer at uses; repeatable')
            command.add_argument('--undef', action='append', default=[], help='assume NAME undefined at uses; repeatable')
            command.add_argument('--blame', action='store_true', help='include last editors of changed SCST lines')
    args = parser.parse_args(argv)
    if args.command in ('diff', 'audit') and args.patch and args.json:
        parser.error('--patch and --json are mutually exclusive')
    try:
        linux, scst = Repo(args.linux), Repo(args.scst)
        target, head = linux.resolve(args.to), scst.resolve(args.scst_ref)
        if not linux.files(target, UPSTREAM) or not scst.files(head, DEST):
            raise ToolError('Selected snapshots must contain Linux qla2xxx and SCST qla2x00t-32gbit')
        if args.command == 'audit':
            report = qla2xxx_audit.audit(
                compare(linux, target, scst, head, args.path), linux, scst,
                qla2xxx_audit.profile(args.kernel_version, args.define, args.undef), args.blame)
            if not args.json:
                qla2xxx_audit.print_audit(report, args.patch)
        elif args.command == 'diff':
            report = compare(linux, target, scst, head, args.path)
            if args.patch:
                print_tree_patch(report, linux, scst)
            elif not args.json:
                print(f'Linux: {target}\nSCST:  {head}\nCommitted snapshots only.')
                for entry in report['files']:
                    print(f'{entry["status"]:10} {entry["path"]}')
                print('Counts: ' + json.dumps(report['counts'], sort_keys=True))
        else:
            report = make_history(args, linux, scst, target, head)
            if args.command == 'export':
                report = export_history(report, linux, args.output)
            if not args.json:
                print_history(report)
                if args.command == 'export':
                    print(f'Exported {report["patch_count"]} candidate patches to {args.output}; '
                          f'{report["review_count"]} entries require separate review.')
        if args.json:
            print(json.dumps(report, indent=2))
    except (ToolError, OSError, ValueError) as error:
        print(f'qla2xxx: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
