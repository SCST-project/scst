"""Source-bound exceptions for one semantic rule, never frontend failures."""

import re

TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
                   r'/\*.*?(?:\*/|\Z)|//(?:\\\n|[^\n])*', re.DOTALL)
MARKER = re.compile(r"/\* coccinelle-suppress(-file|-macro|-begin|-end)? "
                    r"([A-Za-z][A-Za-z0-9_-]*)(?: ; ([^\n]*?))? \*/")
DEFINE = re.compile(r"\s*#\s*define\s+([A-Za-z_]\w*)\b")


def source_exceptions(source, name):
    lines = source.splitlines()
    tokens = list(TOKEN.finditer(source))
    code = TOKEN.sub(lambda m: re.sub(r"[^\n]", " ", m[0]), source).splitlines()
    result, opened = [], {}
    for token_index, token in enumerate(tokens):
        if not token[0].startswith(("/*", "//")):
            continue
        line = source.count("\n", 0, token.start()) + 1
        if re.search(r"coccinelle\s*:\s*skip_", token[0]):
            raise ValueError(f"{name}:{line}: native skip annotations hide code from every rule; "
                             "use a rule-specific suppression")
        if "coccinelle-suppress" not in token[0]:
            continue
        match = MARKER.fullmatch(token[0])
        if (not match or lines[line - 1].strip() != token[0]
                or (line > 1 and lines[line - 2].rstrip().endswith("\\"))):
            raise ValueError(f"{name}:{line}: expected a standalone "
                             "coccinelle-suppress[-file|-macro|-begin|-end] RULE ; reason")
        suffix, rule, reason = match.groups()
        if suffix == "-end":
            if rule not in opened:
                raise ValueError(f"{name}:{line}: unmatched suppression end")
            entry = opened.pop(rule)
            if line <= entry["line"]:
                raise ValueError(f"{name}:{line}: empty suppression block")
            entry.update(end_line=line - 1, end_comment_line=line)
            continue
        if not reason or not reason.strip():
            raise ValueError(f"{name}:{line}: suppression requires a reason after ';'")
        if reason.strip() == "See the contract above.":
            previous = tokens[token_index - 1] if token_index else None
            if (previous is None or not previous[0].startswith("/*") or
                    source[previous.end():token.start()].strip() or
                    "coccinelle-suppress" in previous[0]):
                raise ValueError(f"{name}:{line}: missing exception rationale")
            reason = " ".join(re.sub(r"^\s*\* ?", "", row).strip()
                              for row in previous[0][2:-2].splitlines()).strip()
        scope = {None: "line", "-file": "file", "-macro": "macro", "-begin": "block"}[suffix]
        target = line
        while target < len(code) and not code[target].strip():
            target += 1
        if scope == "file":
            if any(row.strip() for row in code[:line - 1]):
                raise ValueError(f"{name}:{line}: file suppression must precede source code")
            target, end, label = 0, len(lines), name
        else:
            if target >= len(code):
                raise ValueError(f"{name}:{line}: suppression must precede source code")
            end, label = target + 1, f"{name}:{target + 1}"
            if scope == "macro":
                macro = DEFINE.match(code[target])
                if not macro:
                    raise ValueError(f"{name}:{line}: macro suppression must precede #define")
                label = macro[1]
                while lines[end - 1].rstrip().endswith("\\"):
                    end += 1
                    if end > len(lines):
                        raise ValueError(f"{name}:{line}: incomplete annotated macro")
        entry = dict(file=name, comment_line=line, line=target + 1, end_line=end,
                     scope=scope, target=label, rule=rule, reason=reason.strip())
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
    from lint_scope import git_names, in_scope

    if (root / ".git").exists():
        names = git_names(root, "ls-files", "--cached", "-z", "--",
                          *(":(top,literal)" + path for path in policy["source_roots"]))
    else:
        names = [path.relative_to(root).as_posix() for directory in policy["source_roots"]
                 for path in (root / directory).rglob("*") if path.is_file()]
    entries = []
    for name in sorted(set(names)):
        path = root / name
        if path.suffix not in policy["source_suffixes"] or not path.is_file():
            continue
        for entry in source_exceptions(path.read_text(errors="surrogateescape"), name):
            entry["selected_by_policy"] = in_scope(path, root, "coccicheck", policy=policy)
            entries.append(entry)
    return entries


def match_exception(entries, rule, name, line):
    return next((entry for entry in entries if entry["rule"] == rule
                 and entry["file"] == name and entry["line"] <= line <= entry["end_line"]), None)
