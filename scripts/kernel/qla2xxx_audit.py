# SPDX-License-Identifier: GPL-2.0-only
"""Conservative, review-oriented comparison; not a C compiler or equivalence proof."""

from collections import Counter
import difflib
import re


# Strings precede comments: comment markers inside literals are data. Line
# splicing is done first, as in C translation phase 2, preserving source lines.
LEX = re.compile(
    r'(?P<literal>(?:u8|[LuU])?(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'))'
    r'|(?P<comment>/\*.*?\*/|//[^\n]*)'
    r'|(?P<word>[A-Za-z_]\w*|(?:\d|\.\d)(?:[eEpP][+-]|[\w.])*)'
    r'|(?P<space>\s+)'
    r'|(?P<operator>\%:\%:|>>=|<<=|\.\.\.|->|\+\+|--|<<|>>|<=|>=|==|!='
    r'|&&|\|\||\*=|/=|%=|\+=|-=|&=|\^=|\|=|##|<:|:>|<%|%>|%:|.)', re.S)
DIRECTIVE = re.compile(r'^\s*(?:#|%:)\s*(\w+)\b(.*)$', re.S)
IDENTIFIER = r'[A-Za-z_]\w*'


def source_lines(source):
    """Logical, comment-free lines paired with original physical line numbers."""
    logical, numbers, pending, start = [], [], None, 1
    for number, line in enumerate(source.splitlines(keepends=True), 1):
        if pending is None:
            start = number
            pending = ''
        if line.endswith('\\\n'):
            pending += line[:-2]
            continue
        logical.append(pending + line)
        numbers.append(start)
        pending = None
    if pending is not None:
        logical.append(pending)
        numbers.append(start)
    joined = ''.join(logical)
    cleaned = LEX.sub(lambda m: re.sub(r'[^\n]', ' ', m.group())
                      if m.lastgroup == 'comment' else m.group(), joined)
    return list(zip(cleaned.splitlines(keepends=True), numbers))


def tokens(lines):
    """C preprocessing tokens plus opaque directives with their source locations.

    Keep directive whitespace: macro function/object distinction and #/##
    stringification can make it significant. This deliberately under-normalizes.
    """
    result = []
    for line, number in lines:
        if re.match(r'^\s*(?:#|%:)', line):
            result.append((line.strip(), number))
        else:
            result.extend((m.group(), number) for m in LEX.finditer(line)
                          if m.lastgroup not in ('space', 'comment'))
    return result


class Condition:
    """Small integer/boolean subset, with unknown values propagated explicitly."""
    def __init__(self, expression, defines, kernel):
        self.items = [m.group() for m in LEX.finditer(expression)
                      if m.lastgroup not in ('space', 'comment')] + ['<end>']
        self.index = 0
        self.defines = defines
        self.kernel = kernel

    def take(self):
        token = self.items[self.index]
        self.index += 1
        return token

    def accept(self, token):
        if self.items[self.index] == token:
            self.index += 1
            return True
        return False

    def require(self, token):
        if not self.accept(token):
            raise ValueError('Unsupported preprocessor expression')

    def atom(self):
        token = self.take()
        if token == '(':
            value = self.expression()
            self.require(')')
            return value
        if token in ('!', '+', '-'):
            value = self.atom()
            if value is None:
                return None
            return int(not value) if token == '!' else value if token == '+' else -value
        if token == 'defined':
            bracket = self.accept('(')
            name = self.take()
            if not re.fullmatch(IDENTIFIER, name):
                raise ValueError('Invalid defined operand')
            if bracket:
                self.require(')')
            return int(self.defines[name] is not None) if name in self.defines else None
        if re.fullmatch(r'0[xX][0-9a-fA-F]+|0|[1-9][0-9]*', token):
            value = int(token, 16 if token.lower().startswith('0x') else 10)
            return value if value <= 0x7fffffff else None
        if re.fullmatch(IDENTIFIER, token):
            if self.accept('('):
                args = []
                if not self.accept(')'):
                    while True:
                        args.append(self.expression())
                        if self.accept(')'):
                            break
                        self.require(',')
                if (token == 'KERNEL_VERSION' and self.kernel and len(args) == 3
                        and all(v is not None and 0 <= v <= 255 for v in args)):
                    return (args[0] << 16) + (args[1] << 8) + args[2]
                return None
            return (self.defines[token] or 0) if token in self.defines else None
        raise ValueError('Unsupported preprocessor token')

    def expression(self, minimum=0):
        precedence = {'||': 1, '&&': 2, '==': 3, '!=': 3,
                      '<': 4, '>': 4, '<=': 4, '>=': 4, '+': 5, '-': 5}
        left = self.atom()
        while self.items[self.index] in precedence:
            op = self.items[self.index]
            level = precedence[op]
            if level < minimum:
                break
            self.take()
            right = self.expression(level + 1)
            if op == '&&' and (left == 0 or right == 0):
                left = 0
            elif op == '||' and ((left is not None and left != 0)
                                or (right is not None and right != 0)):
                left = 1
            elif left is None or right is None:
                left = None
            else:
                left = {'||': lambda: int(bool(left or right)),
                        '&&': lambda: int(bool(left and right)),
                        '==': lambda: int(left == right), '!=': lambda: int(left != right),
                        '<': lambda: int(left < right), '>': lambda: int(left > right),
                        '<=': lambda: int(left <= right), '>=': lambda: int(left >= right),
                        '+': lambda: left + right, '-': lambda: left - right}[op]()
                if not -0x7fffffff <= left <= 0x7fffffff:
                    left = None
        return left

    def value(self):
        try:
            value = self.expression()
            return value if self.items[self.index] == '<end>' else None
        except (ValueError, IndexError, RecursionError):
            return None


def profile(version, definitions, undefined):
    values = {}
    if version:
        if not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', version):
            raise ValueError('--kernel-version requires MAJOR.MINOR[.PATCH]')
        parts = [int(v) for v in version.split('.')]
        if len(parts) == 2:
            parts.append(0)
        if any(p > 255 for p in parts):
            raise ValueError('--kernel-version components must be in 0..255')
        values['LINUX_VERSION_CODE'] = (parts[0] << 16) + (parts[1] << 8) + parts[2]
    for definition in definitions:
        name, _, value = definition.partition('=')
        if (not re.fullmatch(IDENTIFIER, name) or not value
                or not re.fullmatch(r'0[xX][0-9a-fA-F]+|0|[1-9][0-9]*', value)):
            raise ValueError('--define requires NAME=nonnegative-integer')
        number = int(value, 16 if value.lower().startswith('0x') else 10)
        if name in values or name == 'KERNEL_VERSION' or number > 0x7fffffff:
            raise ValueError(f'Conflicting or unsupported definition: {definition}')
        values[name] = number
    for name in undefined:
        if not re.fullmatch(IDENTIFIER, name) or name in values or name == 'KERNEL_VERSION':
            raise ValueError(f'Conflicting or invalid --undef: {name}')
        values[name] = None
    return {'kernel_version': version, 'defines': values,
            'enabled': bool(version or definitions or undefined)}


def project(lines, selected):
    """Evaluate only explicit profile facts; never infer absent macros as zero.

    Local redefinitions invalidate external assumptions even in conditional
    branches. Includes are not expanded: profile facts must hold at their uses.
    Unknown branches remain, with independently decidable nested groups reduced.
    """
    if not selected['enabled']:
        return lines, [], []
    values = dict(selected['defines'])
    redefined = set()
    for line, _ in lines:
        match = re.match(r'^\s*(?:#|%:)\s*(?:define|undef)\s+(' + IDENTIFIER + ')', line)
        if match:
            redefined.add(match[1])
    for name in redefined:
        values.pop(name, None)
    kernel = bool(selected['kernel_version']) and 'KERNEL_VERSION' not in redefined
    decisions = []

    def condition(command, expression):
        if command in ('ifdef', 'ifndef'):
            value = values.get(expression.strip())
            known = expression.strip() in values
            return int((value is not None) == (command == 'ifdef')) if known else None
        return Condition(expression, values, kernel).value()

    def block(index):
        output = []
        while index < len(lines):
            line, number = lines[index]
            directive = DIRECTIVE.match(line)
            command = directive[1] if directive else ''
            if command in ('elif', 'else', 'endif'):
                return output, index
            if command not in ('if', 'ifdef', 'ifndef'):
                output.append(lines[index])
                index += 1
                continue
            branches = []
            saw_else = False
            while True:
                header = lines[index]
                match = DIRECTIVE.match(header[0])
                kind, expression = match.groups()
                if saw_else:
                    raise ValueError(f'Unexpected #{kind} after #else at line {header[1]}')
                saw_else = kind == 'else'
                value = 1 if saw_else else condition(kind, expression)
                content, end = block(index + 1)
                branches.append((header, value, content))
                if end >= len(lines):
                    raise ValueError(f'Unclosed conditional at line {number}')
                end_kind = DIRECTIVE.match(lines[end][0])[1]
                if end_kind == 'endif':
                    break
                index = end
            chosen, known = None, True
            for branch_number, (_, value, _) in enumerate(branches):
                if value is None:
                    known = False
                    break
                if value:
                    chosen = branch_number
                    break
            decisions.append({'line': number, 'condition': line.strip(),
                              'result': 'selected' if known else 'unknown',
                              'selected_line': branches[chosen][0][1]
                              if known and chosen is not None else None})
            if known:
                if chosen is not None:
                    output.extend(branches[chosen][2])
            else:
                for header, _, content in branches:
                    output.append(header)
                    output.extend(content)
                output.append(lines[end])
            index = end + 1
        return output, index

    output, end = block(0)
    if end != len(lines):
        raise ValueError(f'Unmatched conditional at line {lines[end][1]}')
    assumptions = set(selected['defines']) | ({'KERNEL_VERSION'} if selected['kernel_version'] else set())
    return output, sorted(decisions, key=lambda d: d['line']), sorted(redefined & assumptions)


def line_delta(before, after, matcher=None):
    if matcher is None:
        matcher = difflib.SequenceMatcher(None, before, after, autojunk=False)
    added = removed = 0
    for kind, a, b, c, d in matcher.get_opcodes():
        if kind != 'equal':
            removed += b - a
            added += d - c
    return {'added': added, 'removed': removed}


def unified(before, after, name):
    diff = difflib.unified_diff(before.splitlines(keepends=True),
                                after.splitlines(keepends=True),
                                fromfile='linux/' + name, tofile='scst/' + name)
    return ''.join(line if line.endswith('\n') else line + '\n\\ No newline at end of file\n'
                   for line in diff)


def classify(before, after, path):
    """Review hints, never a claim that a hunk is a safe backport."""
    joined = before + '\n' + after
    if '/qla2x00-target/' in path or re.search(r'\b(?:scst_\w*|SCST_\w*)', joined):
        return 'scst-integration', 'SCST adapter path or SCST symbol in the changed code'
    if re.search(r'\b(?:LINUX_VERSION_CODE|KERNEL_VERSION|RHEL_\w*|HAVE_\w*|QLA_ENABLE_PI'
                 r'|NEW_LIBFC_API|BSG_JOB_TYPE|bsg_job_sense|se_cmd_tag|MAP_QUEUES_RET)\b', joined):
        return 'compatibility-candidate', 'Compatibility wrapper or guard remains; inspect its definition and branches'
    if re.search(r'(?<![=!<>])=(?!=)|\b(?:if|return|goto)\b', joined):
        return 'behavior-candidate', 'Assignment or control flow changed; inspect values and callers'
    calls = r'\b([A-Za-z_]\w*)\s*\('
    if set(re.findall(calls, before)) != set(re.findall(calls, after)):
        return 'behavior-candidate', 'Called or declared function names differ; inspect API semantics'
    return 'needs-review', 'No automatic explanation for the remaining token change'


def scope_hint(lines, number):
    # A column-zero kernel-style function definition, not a C parser. This is
    # only navigation context; line spans and original diff are authoritative.
    text = ''.join(line for line, original in lines if original <= number)
    matches = list(re.finditer(r'^(?:[A-Za-z_]\w*[\t *]+)*([A-Za-z_]\w*)\([^;{}]*\)\s*\{', text, re.M))
    return matches[-1][1] if matches else None


def residual_hunks(before, after, original_before, original_after, path, matcher):
    result = []
    for group in matcher.get_grouped_opcodes(6):
        changes = [op for op in group if op[0] != 'equal']
        entry = {}
        changed_text = []
        for side, stream, source, lower, upper in (
                ('linux', before, original_before, 1, 2),
                ('scst', after, original_after, 3, 4)):
            ids = sorted({stream[i][1] for op in changes for i in range(op[lower], op[upper])})
            # A pure insertion/deletion still has an anchor in the other tree.
            anchor = min(changes[0][lower], len(stream) - 1)
            start = ids[0] if ids else stream[anchor][1] if stream else 1
            stop = ids[-1] if ids else start
            entry[side] = {'start': start, 'end': stop, 'changed_lines': ids,
                           'text': '\n'.join(source.splitlines()[start - 1:stop]),
                           'scope_hint': scope_hint(source_lines(source), start)}
            physical = source.splitlines()
            changed_text.append('\n'.join(physical[n - 1] for n in ids))
        entry['category'], entry['reason'] = classify(*changed_text, path)
        entry['requires_review'] = True
        result.append(entry)
    return result


def audit(report, linux, scst, selected, blame=False):
    report['audit_version'] = 1
    report['profile'] = selected
    report['warnings'] = [
        'Only committed snapshots are inspected; working-tree changes are excluded.',
        'Token equality and conditional projection are not semantic equivalence.',
        'Includes/macros are not expanded. Unknown conditions remain; profile facts '
        'must hold at their uses. Classification and scope names are review hints.',
        'Blame identifies last editors of SCST lines, not necessarily the origin of a difference.']
    for entry in report['files']:
        entry['hunks'] = []
        if entry['status'] == 'identical':
            entry['assessment'] = 'identical'
            continue
        if any(entry[side] and entry[side]['mode'] not in ('100644', '100755')
               for side in ('linux', 'scst')):
            entry['assessment'] = 'special-file-review'
            continue
        blobs = [repo.git('cat-file', 'blob', entry[key]['oid']) if entry[key] else b''
                 for repo, key in ((linux, 'linux'), (scst, 'scst'))]
        if any(b'\0' in blob for blob in blobs):
            entry['assessment'] = 'binary-review'
            continue
        try:
            old, new = [blob.decode('utf-8') for blob in blobs]
        except UnicodeDecodeError:
            entry['assessment'] = 'encoding-review'
            continue
        entry['raw_lines'] = line_delta(old.splitlines(), new.splitlines())
        entry['raw_diff'] = unified(old, new, entry['path'])
        if not entry['path'].endswith(('.c', '.h')):
            entry['assessment'] = 'non-c-review'
            continue
        streams = [source_lines(source) for source in (old, new)]
        lexical = [tokens(lines) for lines in streams]
        projections = [project(lines, selected) for lines in streams]
        projected = [tokens(p[0]) for p in projections]
        for side, (_, decisions, invalidated) in zip(('linux', 'scst'), projections):
            entry[side + '_conditions'] = decisions
            entry[side + '_invalidated_defines'] = invalidated
        old_tokens, new_tokens = [[t for t, _ in stream] for stream in projected]
        # Matching large C files is the expensive step. Reuse its opcodes for
        # both counts and hunks instead of matching the same streams twice.
        matcher = difflib.SequenceMatcher(None, old_tokens, new_tokens, autojunk=False)
        entry['residual_tokens'] = line_delta(old_tokens, new_tokens, matcher)
        entry['hunks'] = residual_hunks(*projected, old, new, entry['path'], matcher)
        if entry['status'] != 'different':
            entry['assessment'] = entry['status'] + '-review'
        elif entry['linux']['mode'] != entry['scst']['mode']:
            entry['assessment'] = 'mode-review'
        elif [t for t, _ in lexical[0]] == [t for t, _ in lexical[1]]:
            entry['assessment'] = 'lexical-only'
        elif not entry['hunks']:
            entry['assessment'] = 'equal-under-profile'
        else:
            entry['assessment'] = 'residual-review'
        if blame and entry['scst'] and entry['hunks']:
            history = scst.text('blame', '--line-porcelain', report['scst_head'], '--', entry['path'])
            origins = {}
            commit, line = None, None
            for record in history.splitlines():
                match = re.fullmatch(r'([0-9a-f]{40}) \d+ (\d+)(?: \d+)?', record)
                if match:
                    commit, line = match[1], int(match[2])
                elif record.startswith('summary ') and line is not None:
                    origins[line] = {'commit': commit, 'subject': record[8:]}
            for hunk in entry['hunks']:
                evidence = {origins[n]['commit']: origins[n] for n in hunk['scst']['changed_lines']
                            if n in origins}
                hunk['scst_last_editors'] = sorted(evidence.values(), key=lambda e: e['commit'])
    report['assessments'] = dict(Counter(e['assessment'] for e in report['files']))
    report['hunk_categories'] = dict(Counter(h['category'] for e in report['files'] for h in e['hunks']))
    report['shared_c_totals'] = {
        metric: {direction: sum(e.get(metric, {}).get(direction, 0) for e in report['files']
                               if e['status'] == 'different' and e['path'].endswith(('.c', '.h')))
                 for direction in ('added', 'removed')}
        for metric in ('raw_lines', 'residual_tokens')}
    return report


def print_audit(report, patch=False):
    print(f'Linux: {report["linux_target"]}\nSCST:  {report["scst_head"]}')
    print(f'Profile: {report["profile"]}')
    for warning in report['warnings']:
        print('Note: ' + warning)
    for entry in report['files']:
        if entry['assessment'] == 'identical':
            continue
        print(f'\n{entry["assessment"]}: {entry["path"]} {entry.get("raw_lines", {})}')
        if patch and not entry['hunks'] and entry['assessment'].endswith('-review'):
            print(entry.get('raw_diff', '(non-text difference)'))
        for hunk in entry['hunks']:
            old, new = hunk['linux'], hunk['scst']
            print(f'  {hunk["category"]}: Linux {old["start"]}:{old["end"]} -> '
                  f'SCST {new["start"]}:{new["end"]} '
                  f'({new["scope_hint"] or old["scope_hint"] or "global/declaration"})')
            if patch:
                print('    ' + hunk['reason'])
                for prefix, part in (('-', old), ('+', new)):
                    if part['changed_lines']:
                        for line in part['text'].splitlines():
                            print(prefix + line)
    print('\nAssessments: ' + str(report['assessments']))
    print('Residual hunks: ' + str(report['hunk_categories']))
    print('Shared C sources: ' + str(report['shared_c_totals']))
