"""Read current macro definitions without selecting preprocessor branches."""

import functools
import re

NON_CODE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
                      r'/\*.*?(?:\*/|\Z)|//(?:\\\n|[^\n])*', re.S)


def code(text):
    return NON_CODE.sub(lambda match: re.sub(r"[^\n]", " ", match[0]), text)


@functools.lru_cache(maxsize=None)
def macros(root, name):
    text = (root / name).read_text()
    lines = text.splitlines()
    clean = code(text).splitlines()
    result = []
    index = 0
    while index < len(lines):
        start = index
        while lines[index].endswith("\\"):
            index += 1
            if index == len(lines):
                raise ValueError(f"Unterminated macro continuation: {name}:{start + 1}")
        text = "\n".join(lines[start:index + 1])
        logical = text.replace("\\\n", "")
        masked = "\n".join(clean[start:index + 1]).replace("\\\n", "")
        match = re.match(r"\s*#\s*define\s+(\w+)(\([^)]*\))?", masked)
        if match:
            result.append(dict(file=name, name=match[1], start=start + 1, end=index + 1,
                               definition=text, parameters=match[2][1:-1] if match[2] else None,
                               body=logical[match.end():].lstrip()))
        index += 1
    return result


def definitions(root, item):
    result = [dict(item, **entry) for entry in macros(root, item["file"])
              if entry["name"] == item["name"]]
    if not result:
        raise ValueError(f"Missing Coccinelle macro: {item['file']}: {item['name']}")
    return result


def single_definition(root, item):
    entries = definitions(root, item)
    if len(entries) != 1:
        raise ValueError(f"Ambiguous Coccinelle macro: {item['file']}: {item['name']}")
    return entries[0]
