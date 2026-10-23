"""Identify complete standalone macro errors without claiming body coverage."""

import re
from pathlib import Path

from coccinelle.source import macros


def prefix_is_context(root, item, prefix):
    """Native error excerpts start on the preceding completed token's line."""
    if not prefix:
        return True
    lines = (root / item["file"]).read_text().splitlines()
    start = item["start"] - 1 - len(prefix)
    if start < 0 or prefix != [" ".join(line.split())
                              for line in lines[start:item["start"] - 1]]:
        return False
    text = "\n".join(prefix)
    text = re.sub(r"/\*.*?\*/|//[^\n]*", lambda match: "\n" * match[0].count("\n"),
                  text, flags=re.S)
    code = [(start + index, line.strip()) for index, line in enumerate(text.splitlines())
            if line.strip() and not line.lstrip().startswith("#")]
    if not code:
        return True
    if len(code) != 1:
        return False
    index, line = code[0]
    beginning = index
    while beginning > 0 and lines[beginning - 1].endswith("\\"):
        beginning -= 1
    if beginning < index and re.match(r"\s*#\s*define\s+", lines[beginning]):
        return True
    # A preceding closing brace or prototype is context, not a skipped body.
    return line in {"}", "};"} or (line.endswith(";") and not any(c in line for c in "{}="))


def macro_definition_error(root, lines, index):
    """Recognize a whole current definition, never an invocation or partial block."""
    if lines[index].strip() not in {
            "parse error", "semantic error storage class specified for macro type decl"}:
        return None
    if index + 1 >= len(lines):
        return None
    location = re.fullmatch(
        r"\s*=\s*error in (.+); set verbose_parsing for more info", lines[index + 1])
    if not location:
        return None
    path = Path(location[1])
    try:
        name = (root / path).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None
    end = index + 2
    excerpt = []
    errors = []
    while end < len(lines):
        line = lines[end]
        if line.startswith("badcount:"):
            pass
        elif line.startswith("bad: "):
            excerpt.append(line[5:])
        elif line.startswith("BAD:!!!!! "):
            errors.append(len(excerpt))
            excerpt.append(line[10:])
        else:
            break
        end += 1
    if len(errors) != 1:
        return None

    def normalize(text):
        return " ".join(text.split())

    excerpt = list(map(normalize, excerpt))
    if not (root / name).is_file():
        return None
    for item in macros(root, name):
        expected = list(map(normalize, item["definition"].splitlines()))
        for start in range(len(excerpt) - len(expected) + 1):
            after = start + len(expected)
            if (start <= errors[0] < after and excerpt[start:after] == expected
                    and not any(excerpt[after:])
                    and prefix_is_context(root, item, excerpt[:start])):
                return end, {"file": name, "name": item["name"], "line": item["start"],
                             "message": lines[index].strip(), "excerpt": lines[index:end]}
    return None
