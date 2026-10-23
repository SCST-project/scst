"""Inventory native Cppcheck comments; diagnostic matching belongs to Cppcheck."""

import re
import xml.etree.ElementTree as ET

from analyzer_setup import MODELS

FRONTEND_IDS = {
    "noValidConfiguration", "internalAstError", "syntaxError", "unknownMacro",
    "preprocessorErrorDirective", "internalError", "cppcheckError",
    "directiveAsMacroParameter", "toomanyconfigs",
}
PROTECTED_IDS = FRONTEND_IDS | {
    "checkersReport", "unmatchedSuppression", "missingInclude", "missingIncludeSystem",
}
TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
                   r'/\*.*?(?:\*/|\Z)|//(?:\\\n|[^\n])*', re.DOTALL)
MARKER = re.compile(r"/\* cppcheck-suppress(-begin|-end|-file|-macro)? "
                    r"([a-zA-Z][a-zA-Z0-9]*)(?: symbolName=([a-zA-Z_]\w*))?"
                    r"(?: ; ([^\n]*?))? \*/")
DEFINE = re.compile(r"\s*#\s*define\s+([a-zA-Z_]\w*)\b")


def reason_before(source, tokens, index, *, suffix=None):
    """Find a common rationale across adjacent annotations for one construct."""
    current = tokens[index]
    for previous in reversed(tokens[:index]):
        if (source[previous.end():current.start()].strip()
                or not previous[0].startswith("/*")):
            return ""
        if "cppcheck-suppress" not in previous[0]:
            return " ".join(re.sub(r"^\s*\* ?", "", line).strip()
                            for line in previous[0][2:-2].splitlines()).strip()
        marker = MARKER.fullmatch(previous[0])
        if (not marker or suffix == "-file" or marker[1] in ("-end", "-file")
                or marker[4] not in (None, "See the contract above.")):
            return ""
        current = previous
    return ""


def source_exceptions(source, name):
    """Validate the supported native subset without emulating native matching."""
    tokens = list(TOKEN.finditer(source))
    lines = source.splitlines()
    code = TOKEN.sub(lambda m: re.sub(r"[^\n]", " ", m[0]), source).splitlines()
    result, opened = [], {}
    for index, token in enumerate(tokens):
        if not token[0].startswith(("/*", "//")) or "cppcheck-suppress" not in token[0]:
            continue
        line = source.count("\n", 0, token.start()) + 1
        marker = MARKER.fullmatch(token[0])
        if (not marker or lines[line - 1].strip() != token[0]
                or (line > 1 and lines[line - 2].rstrip().endswith("\\"))):
            raise ValueError(f"{name}:{line}: expected a standalone "
                             "/* cppcheck-suppress[-begin|-end|-file|-macro] ID "
                             "[symbolName=NAME] ; reason */ comment")
        suffix, rule, symbol, inline_reason = marker.groups()
        if rule in PROTECTED_IDS:
            raise ValueError(f"{name}:{line}: cannot suppress analysis integrity diagnostic {rule}")
        key = rule, symbol
        if suffix == "-end":
            if key not in opened:
                raise ValueError(f"{name}:{line}: unmatched suppression end")
            entry = opened.pop(key)
            if line <= entry["line"]:
                raise ValueError(f"{name}:{line}: empty suppression block")
            entry["end_line"] = line - 1
            entry["end_comment_line"] = line
            continue
        # Retain the former spelling for existing source exports and fixtures.
        reason = (inline_reason.strip() if inline_reason is not None and
                  inline_reason.strip() != "See the contract above." else
                  reason_before(source, tokens, index, suffix=suffix))
        if not reason:
            raise ValueError(f"{name}:{line}: suppression requires a reason after ';'")
        target = next((i for i in range(line, len(code)) if code[i].strip()), None)
        if target is None:
            raise ValueError(f"{name}:{line}: suppression has no following source code")
        scope = {None: "line", "-begin": "block", "-file": "file", "-macro": "macro"}[suffix]
        entry = {"file": name, "comment_line": line, "line": target + 1,
                 "end_line": target + 1, "scope": scope, "target": f"{name}:{target + 1}",
                 "rule": rule, "symbol": symbol, "reason": reason,
                 "source": lines[target].strip()}
        if scope == "file":
            if any(row.strip() for row in code[:line - 1]):
                raise ValueError(f"{name}:{line}: file suppression must precede all code")
            entry.update(line=1, end_line=len(lines), target=name)
        elif scope == "macro":
            macro = DEFINE.match(code[target])
            if not macro:
                raise ValueError(f"{name}:{line}: macro suppression must precede #define")
            end = target
            while lines[end].rstrip().endswith("\\"):
                end += 1
                if end >= len(lines):
                    raise ValueError(f"{name}:{line}: incomplete annotated macro")
            entry.update(end_line=end + 1, target=f"expansions of {macro[1]}")
        elif scope == "block":
            if key in opened:
                raise ValueError(f"{name}:{line}: duplicate open suppression block")
            opened[key] = entry
        if symbol:
            entry["target"] += f" / symbolName={symbol}"
        result.append(entry)
    if opened:
        entry = next(iter(opened.values()))
        raise ValueError(f"{name}:{entry['comment_line']}: unterminated suppression block")
    return result


def inventory(root, policy):
    """List source declarations, not suppression hits or configured input coverage."""
    from lint_scope import git_names, in_scope, tracked_sources

    # Include new source/header files: an explicit input or an included header can
    # be analyzed before it is staged. Third-party submodules remain opt-in.
    if (root / ".git").exists():
        names = git_names(root, "ls-files", "--cached", "--others", "--exclude-standard",
                          "-z", "--",
                          *(":(top,literal)" + path for path in policy["source_roots"]))
        names.extend(path.relative_to(root).as_posix()
                     for path in tracked_sources(root, "cppcheck"))
    else:
        # Explicit-file wrappers also support source exports without Git metadata.
        names = [path.relative_to(root).as_posix() for directory in policy["source_roots"]
                 for path in (root / directory).rglob("*") if path.is_file()]
    model_names = {model["path"] for model in MODELS["cppcheck"]}
    names.extend(model_names)
    result = []
    for name in sorted(set(names)):
        path = root / name
        if path.suffix not in policy["source_suffixes"] or not path.is_file():
            continue
        for entry in source_exceptions(path.read_text(errors="surrogateescape"), name):
            entry["selected_by_policy"] = in_scope(path, root, "cppcheck", policy=policy)
            entry["model"] = name in model_names
            result.append(entry)
    return result


def validate_ids(entries, errorlist):
    """An unmatched annotation must not turn an unknown diagnostic ID into success."""
    try:
        document = ET.fromstring(errorlist)
    except ET.ParseError as error:
        raise ValueError(f"Invalid Cppcheck diagnostic catalogue: {error}") from error
    ids = {item.get("id") for item in document.findall("errors/error") if item.get("id")}
    if document.tag != "results" or not ids:
        raise ValueError("Cppcheck diagnostic catalogue is empty or incomplete")
    unknown = sorted({entry["rule"] for entry in entries} - ids)
    if unknown:
        raise ValueError("Unknown inline Cppcheck diagnostic IDs: " + ", ".join(unknown))


def unmatched_advice(entries, policy):
    """Allow notices only at inventoried declarations whose IDs were validated."""
    setting = policy["unmatched_inline_advice"]
    if not setting["enabled"]:
        return []
    return [{"id": "unmatchedSuppression", "file": entry["file"], "line": line,
             "unmatched_id": entry["rule"], "reason": setting["reason"]}
            for entry in entries for line in sorted({entry["comment_line"], entry["line"]})]


def excluded_sources(root, policy):
    """Resolve exact external QLogic files; preserve the nested SCST target."""
    result = {}
    for group in policy["excluded_diagnostic_sources"]:
        directory = (root / group["directory"]).resolve()
        retained = [(root / name).resolve() for name in group["keep"]]
        for path in directory.rglob("*"):
            source = path.resolve()
            if (source.suffix not in {".c", ".h"} or not source.is_file() or
                    not source.is_relative_to(directory) or not source.is_relative_to(root) or
                    any(source.is_relative_to(keep) for keep in retained)):
                continue
            result[source.relative_to(root).as_posix()] = group["reason"]
    return result


def excluded_diagnostic(root, row, sources):
    """Never exclude frontend failures or diagnostics also pointing into owned code."""
    if row["id"] in PROTECTED_IDS or not row["locations"]:
        return None
    reasons = []
    for location in row["locations"]:
        if not location.get("file"):
            return None
        path = (root / location["file"]).resolve()
        if not path.is_relative_to(root) or path.relative_to(root).as_posix() not in sources:
            return None
        reasons.append(sources[path.relative_to(root).as_posix()])
    return "; ".join(sorted(set(reasons)))
