"""Recognize reviewed source forms, never arbitrary diagnostic text."""

import fnmatch
import re

TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
                   r'/\*.*?(?:\*/|\Z)|//(?:\\\n|[^\n])*', re.DOTALL)
PP_TOKEN = re.compile(r"\s*(defined\b|[A-Za-z_]\w*|0[xX][0-9a-fA-F]+|[0-9]+|"
                      r"&&|\|\||==|!=|<=|>=|>>|[()!,<>-])")
INTEGER = re.compile(r"(?:0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)")
STRING = r'"(?:\\[^\n]|[^"\\\n])*"'
LOG_CALL = re.compile(r"([ \t]*)([A-Za-z_]\w*)\([ \t]*(" + STRING +
                      r"(?:[ \t]*" + STRING + r")*)[ \t]*(?:,|\);)[ \t]*")


def version_expression(text, policy):
    """Allow known version comparisons, defined() guards and Boolean grouping."""
    tokens = []
    while text.strip():
        match = PP_TOKEN.match(text)
        if not match:
            return False
        tokens.append(match[1])
        text = text[match.end():]
    codes = {item["name"]: item for item in policy["code_macros"]}
    integers = set(policy["integer_macros"])
    position = comparisons = 0

    def take(expected=None):
        nonlocal position
        if position == len(tokens) or (expected is not None and tokens[position] != expected):
            raise ValueError("unexpected version-expression token")
        value = tokens[position]
        position += 1
        return value

    def accept(value):
        if position < len(tokens) and tokens[position] == value:
            take()
            return True
        return False

    def integer():
        if not INTEGER.fullmatch(take()):
            raise ValueError("expected an integer literal")

    def atom():
        nonlocal comparisons
        if accept("!"):
            if position == len(tokens) or tokens[position] not in {"defined", "(", "!"}:
                raise ValueError("expected a negated guard or grouped expression")
            atom()
        elif accept("("):
            expression()
            take(")")
        elif accept("defined"):
            parens = accept("(")
            if not re.fullmatch(r"[A-Za-z_]\w*", take()):
                raise ValueError("expected a feature macro")
            if parens:
                take(")")
        else:
            macro = take()
            if macro not in codes and macro not in integers:
                raise ValueError("unknown version macro")
            # Vendor headers can define an empty macro; the existing - 0
            # spelling keeps those comparisons valid in the preprocessor.
            if accept("-"):
                take("0")
            shifted = macro in codes and accept(">>")
            if shifted:
                take("8")
            if take() not in {"<", ">", "<=", ">=", "==", "!="}:
                raise ValueError("expected a version comparison")
            if macro in integers:
                integer()
            else:
                item = codes[macro]
                take(item["constructor"])
                take("(")
                for index in range(item["arguments"]):
                    if index:
                        take(",")
                    integer()
                take(")")
                if shifted:
                    take(">>")
                    take("8")
            comparisons += 1

    def conjunction():
        atom()
        while accept("&&"):
            atom()

    def expression():
        conjunction()
        while accept("||"):
            conjunction()

    try:
        expression()
        return position == len(tokens) and comparisons > 0
    except (ValueError, RecursionError):
        return False


def source_layouts(source, name, policy):
    """Map exact physical lines to policy exceptions using complete source."""
    raw = source.split("\n")
    logical = []
    start = 0
    while start < len(raw):
        end = start
        while raw[end].endswith("\\") and end + 1 < len(raw):
            end += 1
        pieces = [row[:-1] if index < end else row
                  for index, row in enumerate(raw[start:end + 1], start)]
        logical.append((start, end, pieces))
        start = end + 1
    # C splices physical lines before recognizing comments and literals;
    # even a comment delimiter can be split by a backslash-newline pair.
    text = "\n".join("".join(pieces) for _, _, pieces in logical)
    # Literal contents must not become code or disappear into an otherwise
    # valid expression such as '"hidden" 0'. Preserve offsets for log calls.
    masked = TOKEN.sub(lambda m: re.sub(r"[^\n]", " " if m[0].startswith(("/*", "//"))
                                        else "\0", m[0]), text).split("\n")
    code = [""] * len(raw)
    result = {}
    for (start, end, pieces), text in zip(logical, masked):
        offset = 0
        for index, piece in enumerate(pieces, start):
            code[index] = text[offset:offset + len(piece)]
            offset += len(piece)
        directive = re.fullmatch(r"\s*#\s*(?:if|elif)\b\s*(.+)", text)
        if (directive and not raw[end].endswith("\\") and
                version_expression(directive[1], policy["version_comparisons"])):
            for index in range(start, end + 1):
                result["CONSTANT_COMPARISON", index + 1] = policy["version_comparisons"]["reason"]
    for index, row in enumerate(raw):
        call = LOG_CALL.fullmatch(row)
        if (not call or len(row.expandtabs(8)) <= policy["max_line_length"] or
                len(row[:call.start(3)].expandtabs(8)) > policy["max_line_length"]):
            continue
        # A call-shaped line inside a comment or string is not a statement.
        if code[index][:call.start(3)] != row[:call.start(3)]:
            continue
        for item in policy["logging_calls"]:
            if call[2] in item["names"] and fnmatch.fnmatchcase(name, item["file_glob"]):
                result["LONG_LINE_STRING", index + 1] = item["reason"]
                break
    return result
