"""Rule-specific comments attached to Checkpatch source locations."""

import fnmatch
import re
from collections import Counter
from pathlib import Path

from style.layouts import source_layouts

DIAGNOSTIC = re.compile(r"^(ERROR|WARNING|CHECK)\b", re.MULTILINE)
TOTAL = re.compile(r"^total: (\d+) errors, (\d+) warnings, (?:(\d+) checks, )?"
                   r"\d+ lines checked$", re.MULTILINE)
SOURCE_DIAGNOSTIC = re.compile(
    r"^(ERROR|WARNING|CHECK):([A-Z][A-Z0-9_]*): [^\n]*\n"
    r"#\d+: FILE: ([^\n]+):(\d+):\n((?: [^\n]*\n)*(?:\+[^\n]*\n)+)", re.MULTILINE)
# These rules print the previous line before the location being diagnosed.
PREVIOUS_CONTEXT = {"PARENTHESIS_ALIGNMENT", "LINE_SPACING"}
# These diagnostics can refer to comments rather than the next C token.
COMMENT_RULES = {"PREFER_FALLTHROUGH", "TYPO_SPELLING"}
TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
                   r'/\*.*?(?:\*/|\Z)|//(?:\\\n|[^\n])*', re.DOTALL)
MARKER = re.compile(r"/\*[ \t]*CHECKPATCH:[ \t]+ignore(-file|-block)?[ \t]+"
                    r"([A-Z][A-Z0-9_]*)"
                    r"[ \t]+--[ \t]+([^\n]+?)[ \t]*\*/")
SUPPRESSION = re.compile(r"/\* checkpatch-suppress(-begin|-end|-file|-macro|-symbol)? "
                         r"([A-Z][A-Z0-9_]*)(?: symbolName=([A-Za-z_]\w*))?"
                         r"(?: ; ([^\n]*?))? \*/")
DEFINE = re.compile(r"[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z_0-9]*)\b")
AGGREGATE = re.compile(r"(typedef\s+)?(struct|union|enum)(?:\s+([A-Za-z_]\w*))?")
ARRAY = re.compile(r"(?:[A-Za-z_]\w*\s+|\*\s*)+([A-Za-z_]\w*)\s*"
                   r"(?:\[[^\[\]{};]*\]\s*)+=\s*")
ATTRIBUTES = r"(?:__[A-Za-z_]\w*(?:\([^;{}]*\))?\s*)*"
SENSE_KEYS = frozenset({
    "NO_SENSE", "RECOVERED_ERROR", "NOT_READY", "MEDIUM_ERROR", "HARDWARE_ERROR",
    "ILLEGAL_REQUEST", "UNIT_ATTENTION", "DATA_PROTECT", "BLANK_CHECK",
    "COPY_ABORTED", "ABORTED_COMMAND", "VOLUME_OVERFLOW", "MISCOMPARE", "COMPLETED",
})
SENSE_BYTE = r"(0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)"
SENSE_TUPLE = re.compile(r"\s*#\s*define\s+[A-Za-z_]\w*\s+([A-Z_]+)\s*,\s*" +
                         SENSE_BYTE + r"\s*,\s*" + SENSE_BYTE + r"\s*")


def validate_sense_block(source, entry, end_line, name):
    """Accept only object-like sense-key/ASC/ASCQ definitions in this range."""
    # Keep string/character literals visible: masking them could turn an
    # invalid replacement such as '"text" 0' into an apparently valid byte.
    text = TOKEN.sub(lambda m: re.sub(r"[^\n]", " ", m[0])
                     if m[0].startswith(("/*", "//")) else m[0], source)
    start = entry["comment_end_line"]
    definitions = 0
    for line, value in enumerate(text.split("\n")[start:end_line - 1], start + 1):
        if not value.strip():
            continue
        match = SENSE_TUPLE.fullmatch(value)
        if (not match or match[1] not in SENSE_KEYS or
                any(int(byte, 16 if byte.lower().startswith("0x") else 10) > 255
                    for byte in match.groups()[1:])):
            raise ValueError(f"{name}:{line}: COMPLEX_MACRO block requires "
                             "single-line object-like sense-key, ASC, ASCQ definitions")
        definitions += 1
    if not definitions:
        raise ValueError(f"{name}:{entry['comment_line']}: empty sense-code block")


def block_end(code, start, name):
    """Bound a named aggregate or array initializer, never a function body."""
    text = "\n".join(code[start:])
    opening = text.find("{")
    prefix = text[:opening].strip() if opening >= 0 else ""
    aggregate = AGGREGATE.fullmatch(prefix)
    array = ARRAY.fullmatch(prefix)
    if not (array or (aggregate and (aggregate[1] or aggregate[3]))):
        raise ValueError(f"{name}:{start + 1}: ignore-block requires a named "
                         "struct/union/enum definition or array initializer")
    target = f"{aggregate[2]} {aggregate[3]}" if aggregate else array[1]
    stack = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for offset in range(opening, len(text)):
        char = text[offset]
        if char in {"\0", "#"}:
            raise ValueError(f"{name}:{start + 1}: incomplete or preprocessed annotated block; "
                             "use a smaller exception or complete source context")
        if char in "([{":
            stack.append(char)
        elif char in ")]}":
            if not stack or stack.pop() != pairs[char]:
                break
            if not stack:
                suffix = (r"([A-Za-z_]\w*)\s*;"
                          if aggregate and aggregate[1] else ";")
                tail = re.match(r"\s*" + ATTRIBUTES + suffix, text[offset + 1:])
                if not tail:
                    break
                if aggregate and aggregate[1]:
                    target = f"typedef {tail[1]}"
                end = offset + 1 + tail.end()
                # A line-based diagnostic must not include a second declaration.
                if text[end:].split("\n", 1)[0].strip():
                    break
                return start + text[:end].count("\n") + 1, target
    raise ValueError(f"{name}:{start + 1}: incomplete or unsupported annotated block")


def source_exceptions(source, name):
    """Reject malformed markers; strings and unrelated comments are not markers."""
    lines = source.split("\n")
    tokens = list(TOKEN.finditer(source))
    comments = {source.count("\n", 0, token.start()): token
                for token in tokens if token[0].startswith(("/*", "//"))}
    code = TOKEN.sub(lambda m: re.sub(r"[^\n]", " ", m[0]), source).split("\n")
    result, opened = [], {}
    for token_index, token in enumerate(tokens):
        if not token[0].startswith(("/*", "//")) or not any(
                marker in token[0] for marker in ("CHECKPATCH:", "checkpatch-suppress")):
            continue
        line = source.count("\n", 0, token.start()) + 1
        comment_end = line + token[0].count("\n")
        native_style = "checkpatch-suppress" in token[0]
        # Wrapped comments keep reasons readable even beside deeply indented
        # arguments. The complete comment must still occupy its own lines.
        text = "/* " + " ".join(re.sub(r"^\s*\* ?", "", row).strip()
                                  for row in token[0][2:-2].splitlines()).strip() + " */"
        marker = (SUPPRESSION if native_style else MARKER).fullmatch(text)
        if (not token[0].startswith("/*") or not token[0].endswith("*/") or not marker
                or "\n".join(lines[line - 1:comment_end]).strip() != token[0]
                or (line > 1 and lines[line - 2].rstrip().endswith("\\"))):
            raise ValueError(f"{name}:{line}: expected a standalone "
                             "checkpatch-suppress[-begin|-end|-file|-macro] RULE ; reason comment")
        if native_style:
            suffix, rule, symbol, reason = marker.groups()
        else:
            suffix, rule, reason = marker.groups()
            symbol = None
        if (suffix == "-symbol") != bool(symbol) or (symbol and rule != "CAMELCASE"):
            raise ValueError(f"{name}:{line}: symbol exceptions require CAMELCASE and symbolName")
        if suffix == "-end":
            if rule not in opened:
                raise ValueError(f"{name}:{line}: unmatched suppression end")
            entry = opened.pop(rule)
            if line <= entry["line"] or any("\0" in row for row in
                                            code[entry["line"] - 1:line - 1]):
                raise ValueError(f"{name}:{line}: empty or incomplete suppression block")
            if rule == "COMPLEX_MACRO":
                validate_sense_block(source, entry, line, name)
            entry.update(end_line=line - 1, end_comment_line=line)
            continue
        if not reason or not reason.strip():
            raise ValueError(f"{name}:{line}: suppression requires a reason after ';'")
        annotation_start = line
        if reason.strip() == "See the contract above.":
            previous = tokens[token_index - 1] if token_index else None
            if (previous is None or not previous[0].startswith("/*") or
                    source[previous.end():token.start()].strip() or
                    "checkpatch-suppress" in previous[0]):
                raise ValueError(f"{name}:{line}: missing exception rationale")
            reason = " ".join(re.sub(r"^\s*\* ?", "", row).strip()
                              for row in previous[0][2:-2].splitlines()).strip()
            annotation_start = source.count("\n", 0, previous.start()) + 1
        scope = {None: "line", "-file": "file", "-block": "block",
                 "-begin": "block", "-macro": "macro", "-symbol": "symbol"}[suffix]
        if scope == "file":
            if any(row.strip() for row in code[:line - 1]):
                raise ValueError(f"{name}:{line}: ignore-file must be in the file header "
                                 "before code or preprocessor directives")
            result.append({"file": name, "comment_line": line, "line": 1,
                           "end_line": len(lines) - int(lines[-1] in {"", "\0"}),
                           "scope": scope, "target": name, "rule": rule,
                           "reason": reason.strip(), "source": "whole file"})
            continue
        target = comment_end
        # Consecutive markers may explain different rules for the same construct.
        comment = None
        while target < len(lines) and (not code[target].strip() if native_style else
                                      MARKER.fullmatch(lines[target].strip())):
            candidate = comments.get(target)
            if (native_style and scope == "line" and rule in COMMENT_RULES and candidate
                    and "checkpatch-suppress" not in candidate[0]):
                comment = candidate
                break
            target += 1
        if target >= len(code) or (not code[target].strip() and comment is None) or code[target] == "\0":
            raise ValueError(f"{name}:{line}: Checkpatch comment must precede source code")
        macro = DEFINE.match(code[target]) if scope == "macro" or (
            not native_style and scope == "line") else None
        if scope == "macro" and not macro:
            raise ValueError(f"{name}:{line}: macro suppression must precede #define")
        if rule == "COMPLEX_MACRO" and not macro and suffix != "-begin":
            raise ValueError(f"{name}:{line}: COMPLEX_MACRO comment must precede #define")
        end = target + 1 + (comment[0].count("\n") if comment else 0)
        label = f"{name}:{target + 1}"
        if suffix == "-block":
            end, label = block_end(code, target, name)
        while macro and lines[end - 1].rstrip().endswith("\\"):
            end += 1
            if (end > len(lines) or lines[end - 1] == "\0"
                    or (end == len(lines) and not lines[end - 1])):
                raise ValueError(f"{name}:{line}: incomplete annotated macro")
        entry = {"file": name, "comment_line": line, "line": target + 1,
                 "end_line": end, "scope": "macro" if macro else scope,
                 "target": macro[1] if macro else label,
                 "rule": rule, "reason": reason.strip(),
                 "source": lines[target].strip()}
        entry["comment_end_line"] = comment_end
        if symbol:
            if not re.search(r"\b" + re.escape(symbol) + r"\b", code[target]):
                raise ValueError(f"{name}:{line}: annotated source does not use {symbol}")
            entry["symbol"] = symbol
        if rule == "PREFER_FALLTHROUGH":
            # Native Checkpatch also diagnoses the rule name and its rationale.
            # Account for this rule only, on the verified annotation lines.
            entry["annotation_start"] = annotation_start
        if macro:
            entry["macro"] = macro[1]
        if suffix == "-begin":
            if rule in opened:
                raise ValueError(f"{name}:{line}: duplicate open suppression block")
            opened[rule] = entry
        result.append(entry)
    if opened:
        entry = next(iter(opened.values()))
        raise ValueError(f"{name}:{entry['comment_line']}: unterminated suppression block")
    return result


def inventory(root, policy):
    """Inspect tracked source comments, including files outside effective scope."""
    from lint_scope import git_names, in_scope

    if (root / ".git").exists():
        names = git_names(root, "ls-files", "--cached", "-z", "--",
                          *(":(top,literal)" + path for path in policy["source_roots"]))
    else:
        names = [path.relative_to(root).as_posix() for directory in policy["source_roots"]
                 for path in (root / directory).rglob("*") if path.is_file()]
    result = []
    for name in sorted(set(names)):
        path = root / name
        if path.suffix not in policy["source_suffixes"] or not path.is_file():
            continue
        for entry in source_exceptions(path.read_text(errors="surrogateescape"), name):
            entry["selected_by_policy"] = in_scope(path, root, "checkpatch", policy=policy)
            result.append(entry)
    return result


def layout_reason(rule, name, quoted, policy):
    """Apply only reviewed table forms, after source-context verification."""
    if rule == "PARENTHESIS_ALIGNMENT" and len(quoted) == 2:
        opening = re.fullmatch(r"([ \t]*)([A-Za-z_]\w*)\([^\n]*,", quoted[0])
        indentation = re.match(r"[ \t]*", quoted[1])[0]
        if not opening or len(indentation.expandtabs(8)) != len(opening[1].expandtabs(8)) + 8:
            return None
        for item in policy["macro_body_layouts"]:
            if (item["macro"] == opening[2] and fnmatch.fnmatchcase(name, item["file_glob"])
                    and re.fullmatch(item["first_entry_pattern"], quoted[1].lstrip())):
                return item["reason"]
    if rule in {"LONG_LINE", "LONG_LINE_COMMENT", "LONG_LINE_STRING"} and len(quoted) == 1:
        if len(quoted[0].expandtabs(8)) <= policy["max_line_length"]:
            return None
        normalized = re.sub(r"[ \t]+", " ", quoted[0].strip())
        for item in policy["line_layouts"]:
            if (rule == item["rule"] and fnmatch.fnmatchcase(name, item["file_glob"])
                    and re.fullmatch(item["source_pattern"], normalized)):
                return item["reason"]
    return None


def effective_totals(text):
    """Replace native conclusions with per-input totals after policy application."""
    lines = []
    counts = Counter()
    exempt = 0
    boilerplate = {
        "NOTE: For some of the reported defects, checkpatch may be able to",
        "      mechanically convert to the typical style using --fix or --fix-inplace.",
    }
    for line in text.splitlines(keepends=True):
        value = line.rstrip("\n")
        if TOTAL.fullmatch(value):
            lines.append(line.replace("total: ", "total (before exemptions): ", 1))
            lines.append(f"total (after policy): {counts['ERROR']} errors, "
                         f"{counts['WARNING']} warnings, {counts['CHECK']} checks; "
                         f"{exempt} exempt diagnostics\n")
            counts.clear()
            exempt = 0
        elif value in boilerplate or re.fullmatch(
                r".+ has (?:style problems, please review|no obvious style problems "
                r"and is ready for submission)\.", value):
            continue
        else:
            match = re.match(r"^(ERROR|WARNING|CHECK):", value)
            if match:
                counts[match[1]] += 1
            exempt += value.startswith("EXEMPT:")
            lines.append(line)
    return "".join(lines)


def apply_exceptions(report, root, sources, policy=None, *, symbol_sources=None):
    """Annotate exact locations; certify success only with complete accounting."""
    if policy is None:
        from analyzer_policy import load

        policy = load("checkpatch")
    text = report.decode("utf-8", errors="surrogateescape")
    exempt = Counter()
    entries = {name: source_exceptions(source, name) for name, source in sources.items()}
    symbols = [entry for name, source in (symbol_sources or sources).items()
               for entry in source_exceptions(source, name) if entry.get("symbol")]
    layouts = {}

    def annotate(match):
        path = Path(match[3])
        if path.is_absolute():
            try:
                path = path.relative_to(root)
            except ValueError:
                return match[0]
        name = path.as_posix()
        if name not in entries:
            try:
                name = Path(match[3]).resolve().relative_to(root).as_posix()
            except ValueError:
                return match[0]
        line = int(match[4])
        quoted = [row[1:] for row in match[5].splitlines()]
        start = line - len(quoted) if match[2] in PREVIOUS_CONTEXT else line - 1
        if name not in sources or start < 0:
            return match[0]
        if sources[name].split("\n")[start:start + len(quoted)] != quoted:
            return match[0]
        for entry in entries.get(name, []):
            annotation = (match[2] == "PREFER_FALLTHROUGH" and
                          entry.get("annotation_start", entry["comment_line"]) <= line <=
                          entry.get("comment_end_line", entry["comment_line"]))
            if (entry.get("symbol") or entry["rule"] != match[2] or
                    not (annotation or entry["line"] <= line <= entry["end_line"])):
                continue
            exempt[entry["rule"]] += 1
            target = f"{entry['scope']} {entry['target']}"
            return ("EXEMPT" + match[0][len(match[1]):] +
                    f"  Reason ({target}): {entry['reason']}\n")
        # Match the reviewed identifier, independently of the first-use location
        # chosen by Checkpatch's per-process CamelCase cache.
        word = re.match(r"(?:ERROR|WARNING|CHECK):CAMELCASE: Avoid CamelCase: <([A-Za-z_]\w*)>\n",
                        match[0])
        if word and re.search(r"\b" + re.escape(word[1]) + r"\b", "\n".join(quoted)):
            for entry in symbols:
                if entry["symbol"] == word[1]:
                    exempt["CAMELCASE"] += 1
                    return ("EXEMPT" + match[0][len(match[1]):] +
                            f"  Reason (symbol {word[1]}, {entry['file']}:{entry['line']}): "
                            f"{entry['reason']}\n")
        if name not in layouts:
            layouts[name] = source_layouts(sources[name], name, policy)
        reason = layouts[name].get((match[2], line)) or layout_reason(match[2], name, quoted, policy)
        if reason:
            exempt[match[2]] += 1
            return ("EXEMPT" + match[0][len(match[1]):] +
                    f"  Reason (policy layout): {reason}\n")
        return match[0]

    selected = SOURCE_DIAGNOSTIC.sub(annotate, text)
    selected = effective_totals(selected)
    counts = Counter(DIAGNOSTIC.findall(text))
    totals = Counter()
    summaries = TOTAL.findall(text)
    for errors, warnings, checks in summaries:
        totals.update(ERROR=int(errors), WARNING=int(warnings), CHECK=int(checks or 0))
    # Missing/malformed summaries, unknown diagnostics and partial reports cannot
    # turn a failing tool invocation into success. Stderr is checked by the caller.
    accounted = bool(exempt and summaries and counts == +totals
                     and sum(counts.values()) == sum(exempt.values()))
    return selected.encode("utf-8", errors="surrogateescape"), exempt, accounted
