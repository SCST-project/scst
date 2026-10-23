"""Readable Make and CI evidence; classification belongs to native analyzer drivers.

Raw streams and machine reports remain authoritative and are never rewritten.
"""

from collections import Counter
from functools import partial
from pathlib import Path
import json
import re

from lint_common import report_section
from sparse_smatch.check import DIAGNOSTIC


def show_result(report, log):
    text = render(report, log)
    Path(log).with_suffix(".summary.log").write_text(text)
    print(text, end="", flush=True)

def build_diagnostics(path, *, failed=False, exclude_lines=()):
    """Retain build/environment diagnostics with their nearby source context."""
    if not Path(path).is_file():
        return []
    lines = Path(path).read_text(errors="replace").splitlines()
    blocks = Counter()
    diagnostic = re.compile(r"\b(?:warning|error|fatal error):|undefined reference|"
                            r"undefined symbol|\*\*\*|Skipping BTF generation", re.IGNORECASE)
    for index, line in enumerate(lines):
        if line not in exclude_lines and diagnostic.search(line):
            block = [line]
            for following in range(index + 1, min(index + 5, len(lines))):
                text = lines[following]
                if (not text.startswith("  ") or diagnostic.search(text) or
                        re.match(r"\s+(?:CC|CHECK|LD|BTF|MODPOST|GEN)\s", text)):
                    break
                block.append(text)
            blocks[tuple(block)] += 1
    result = []
    for block, count in blocks.items():
        result.extend(block)
        if count > 1:
            result.append(f"  Repeated {count} times; all occurrences are in the full log.")
    if failed and not any(re.search(r"error:|undefined|\*\*\*", line, re.IGNORECASE)
                          for line in result):
        result.extend(["Build failure context:", *lines[-24:]])
    return result

LABELS = {"sparse": "Sparse", "smatch": "Smatch", "cppcheck": "Cppcheck",
          "checkpatch": "Checkpatch", "coccicheck": "Coccinelle", "scs_lint": "SCS"}
SEVERITIES = ("fatal error", "error", "warning", "style", "performance", "portability",
              "check", "information", "finding")


def group_lines(groups):
    return [f"{count:7} {severity}: [{rule}]" for (severity, rule), count in sorted(
        groups.items(), key=lambda item: (SEVERITIES.index(item[0][0])
                                         if item[0][0] in SEVERITIES else len(SEVERITIES),
                                         -item[1], item[0][1]))]


def markdown_block(text):
    """Keep diagnostic text literal, including embedded Markdown and HTML."""
    fence = "`" * max(3, 1 + max((len(run) for run in re.findall(r"`+", text)), default=0))
    return f"{fence}text\n{text.rstrip()}\n{fence}\n"


def section(title, lines, *, collapsed=False, markdown=False):
    if not markdown:
        return report_section(title, lines, collapsed=collapsed)
    body = lines if isinstance(lines, str) else "\n".join(lines)
    if collapsed:
        return f"\n<details><summary>{title}</summary>\n\n{markdown_block(body)}\n</details>\n"
    return f"\n**{title}**\n\n{markdown_block(body)}"


def render(report, log, *, include_reports=True, status=None, markdown=False):
    """Format native decisions; grouping never determines the exit status."""
    tool = report["tool"]
    status = report.get("exit_code", 2) if status is None else status
    outcome = report.get("outcome", "incomplete")
    badge = "FAIL" if status else "SKIP" if outcome == "skipped" else "PASS"
    lines = [f"{LABELS[tool]}: {badge}; analysis {outcome} (exit {status})",
             f"Findings: {report.get('remaining', 'unknown')} (blocking)"]
    failures = list(report.get("failures", []))
    active, notices, groups, coverage, details = [], Counter(), Counter(), [], []
    macro_limits, limit_reasons, rule_details, tool_notices = Counter(), set(), [], []
    checker_details = {}
    part = partial(section, markdown=markdown)
    native_lines = set()
    checked = report.get("checked_files", [])
    units = tool in {"sparse", "smatch", "cppcheck"}
    kind = "translation units (.c)" if units else "source files (.c and .h)"
    coverage.append(f"Checked {kind}: {len(checked)}; "
                    f"including {sum('/kunit/' in path for path in checked)} KUnit "
                    f"{'translation units' if units else 'files'}")
    if outcome == "skipped":
        coverage.append("No eligible inputs; no analysis performed.")
    if tool == "cppcheck":
        for row in report.get("profiles", []):
            coverage.append(f"{row['profile']}: complete={row['complete']}, "
                            f"native exit={row['native_status']}, "
                            f"units={row['translation_units']}")
            if row.get("native_status_reason"):
                coverage.append(f"  Native exit explanation: {row['native_status_reason']}")
            inventory = row.get("checker_inventory", {})
            inactive = [checker for checker in inventory.get("checkers", []) if not checker["active"]]
            if inactive:
                coverage.append(f"  {row['profile']}: {len(inactive)} checkers not reported active:")
                reasons = Counter(checker["reason"] for checker in inactive)
                coverage.extend(f"    {count} x {reason}" for reason, count in reasons.items())
                entries = [f"Cppcheck {inventory['version']}; native No entries:"]
                for checker in inactive:
                    requirement = (f"; native require:{checker['requirements']}"
                                   if checker["requirements"] else "")
                    entries.append(f"{checker['name']}: {checker['reason']}{requirement}")
                checker_details.setdefault(tuple(entries), []).append(row["profile"])
            failures.extend(row.get("failures", []))
            for diagnostic in row.get("diagnostics", []):
                if diagnostic.get("excluded"):
                    notices["outside source scope", diagnostic["excluded"]] += 1
                    continue
                if diagnostic.get("advisory"):
                    if diagnostic["id"] == "checkersReport":
                        coverage.append(f"  {row['profile']}: {diagnostic['msg']}")
                        continue
                    notices[diagnostic["id"], diagnostic["advisory"]] += 1
                    continue
                groups[diagnostic["severity"], diagnostic["id"]] += 1
                locations = diagnostic.get("locations", []) or [{}]
                for location in locations:
                    active.append(f"{location.get('file', 'native')}:{location.get('line', '0')}: "
                                  f"{diagnostic['severity']}: {diagnostic['msg']} "
                                  f"[{diagnostic['id']}]")
                    if location.get("info"):
                        active.append("  " + location["info"])
        details.append("Native suppression hit counts: unavailable; suppressed messages are not emitted.")
    elif tool == "coccicheck":
        rules = report.get("rules", [])
        skipped = report.get("skipped_rules", [])
        coverage.append(f"Semantic rules: {len(rules)} run; {len(skipped)} skipped without report mode")
        for path in skipped:
            coverage.append(f"Skipped rule: {path} (no report mode)")
        for row in rules:
            name = Path(row["rule"]).name
            duration = (f", duration={row['duration_seconds']:.1f}s"
                        if "duration_seconds" in row else "")
            rule_details.append(f"{name}: complete={row['complete']}, "
                                f"native exit={row['native_status']}, "
                                f"inputs={len(row['handled'])}{duration}")
            failures.extend(f"{row['rule']}: {value}" for value in row.get("failures", []))
            for item in row.get("diagnostics", []):
                if item.get("exception"):
                    notices["source exception", name] += 1
                else:
                    groups["finding", name] += 1
                    active.append(item["native"])
            for item in row.get("coverage_limits", []):
                macro_limits[item['file'], item['line'], item['name'], item['message']] += 1
                limit_reasons.add(item['reason'])
            for item in row.get("tool_warnings", []):
                tool_notices.append(f"{name}: {item['message']} — {item['reason']}")
        definitions = {(file, line) for file, line, _, _ in macro_limits}
        coverage.append(f"Non-blocking macro definition errors: {sum(macro_limits.values())} "
                        f"occurrences; {len(definitions)} definitions")
        coverage.append("Limits: macro bodies and _Generic associations are not exhaustively "
                        "analyzed; no synthetic macro contexts are checked.")
    elif tool == "checkpatch":
        selected = Path(report.get("selected_log", log))
        if selected.is_file():
            text = selected.read_text(errors="replace")
            active.extend(re.findall(r"^(?:ERROR|WARNING|CHECK):[^\n]+(?:\n(?!\n)[^\n]+)*",
                                     text, re.MULTILINE))
            groups.update((match[1].lower(), match[2] or "unclassified") for match in re.finditer(
                r"^(ERROR|WARNING|CHECK):(?:([A-Z][A-Z0-9_]*):)?", text, re.MULTILINE))
        coverage.append(f"Native completion: {report.get('complete', False)}; "
                        f"file reports: {len(report.get('completed_files', []))}; "
                        f"native exit={report.get('native_status', 'not completed')}")
        if report.get("native_status") == 1:
            coverage.append(f"Native exit explanation: Checkpatch reported findings; "
                            f"{report.get('ignored', 0)} exempted, "
                            f"{report.get('remaining', 0)} active.")
        details.extend(f"{count:7} [{rule}]" for rule, count in sorted(
            report.get("exception_counts", {}).items()))
    elif tool == "scs_lint":
        for item in report.get("diagnostics", []):
            active.append(item["native"])
            groups["error", item["rule"]] += 1
        coverage.extend(["Rules: SCS.1", report.get("parser_runtime", "Parser runtime: unavailable")])
    else:
        directory = report.get("records_directory")
        if directory:
            for path in sorted(Path(directory).glob("*.json")):
                row = json.loads(path.read_text())
                ignored = {item["diagnostic"] for item in row["ignored"]}
                for item in row["ignored"]:
                    notices["matched exception", item["reason"]] += 1
                native = Path(row.get("log", path.with_suffix(".log")))
                if native.is_file():
                    active_context = False
                    for line in native.read_text(errors="replace").splitlines():
                        native_lines.add(line)
                        if line in ignored:
                            active_context = False
                            continue
                        if match := DIAGNOSTIC.match(line.encode()):
                            active_context = True
                            severity = match["severity"].decode().lower()
                            if severity == "warn":
                                severity = "warning"
                            groups[severity, tool] += 1
                            active.append(line)
                        elif active_context and line.startswith((" ", "\t")):
                            active.append(line)
                        elif line.strip():
                            active_context = False
                            # Retain include-stack notes and other native output,
                            # but do not present them as blocking source findings.
                            notices["tool message", line] += 1
                if row.get("state") != "complete" or row["returncode"]:
                    failures.append(f"Incomplete CHECK: {path}; native exit={row['returncode']}")
        coverage.append(f"Kbuild exit={report.get('make_status', 'not completed')}; "
                        f"translation units={report.get('translation_units', 0)}")
    if not active:
        active = ["No diagnostic text captured; inspect the full log."
                  if report.get("remaining") else "None."]
    lines.extend(group_lines(groups))
    if markdown:
        lines = [markdown_block("\n".join(lines))]
    lines.append(part("Active diagnostics", active))
    if failures:
        lines.append(part("Analysis failures", failures))
    lines.append(part("Coverage and completion", coverage))
    for entries, profiles in checker_details.items():
        lines.append(part(f"Checker inventory: {', '.join(profiles)}", [
            "Counts describe registered checker execution, not file coverage or suppression hits.",
            "Native require: lists prerequisites, not the exact reason a checker was inactive.",
            "Explanations do not change native activity flags or analysis status.",
            *entries], collapsed=True))
    if tool_notices:
        lines.append(part("Tool notices", tool_notices))
    if tool in {"sparse", "smatch", "cppcheck"}:
        environment = build_diagnostics(report.get("build_log", log),
                                        failed=outcome == "incomplete", exclude_lines=native_lines)
        if environment:
            btf = [line for line in environment if line.startswith("Skipping BTF generation")]
            other = [line for line in environment if not line.startswith("Skipping BTF generation")]
            if btf:
                lines.append(f"BTF generation skipped for {len(btf)} modules; "
                             "build messages are separate from analyzer findings.")
                lines.append(part("BTF details", btf, collapsed=True))
            if other:
                lines.append(part("Build/environment messages",
                                  ["Separate from analyzer findings:", *other]))
    lines.append(f"Inline exception declarations: {len(report.get('inline_exceptions', []))} "
                 "(not suppression hits)")
    if "ignored" in report:
        lines.append(f"Matched exceptions: {report['ignored']}")
    if notices:
        details.extend(f"{count} x {identifier}: {reason}"
                       for (identifier, reason), count in notices.items())
    if details:
        lines.append(part("Exception and model details", details, collapsed=True))
    if rule_details:
        lines.append(part("Per-rule completion", rule_details, collapsed=True))
    if macro_limits:
        lines.append(part("Macro coverage limitations", [
            *sorted(limit_reasons),
            *(f"{file}:{line}: {message} [{name}] ({count} occurrences)"
              for (file, line, name, message), count in sorted(macro_limits.items())),
            "Original error excerpts remain in the native logs and machine report."], collapsed=True))
    if include_reports:
        paths = [f"Full native log: {log}", f"Machine report: {Path(log).with_suffix('.json')}"]
        if report.get("records_directory"):
            paths.append(f"Per-invocation evidence: {report['records_directory']}")
        lines.append(part("Reports", paths))
    return "\n".join(lines) + "\n"
