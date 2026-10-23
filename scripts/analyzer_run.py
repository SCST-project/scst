#!/usr/bin/env python3
"""Present analyzer runs using SCST's native result records."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
from analyzer_policy import inline_inventory, integration, load_policy, source_policy
from analyzer_report import LABELS, markdown_block, render
from lint_common import Interrupted, entrypoint, print_phase, report_lock, report_section, run
from style.checkpatch import checker_path

ROOT = Path(__file__).resolve().parents[1]
DRIVERS = {"sparse": "sparse_smatch/smp.py", "smatch": "sparse_smatch/smp.py",
           "checkpatch": "style/checkpatch.py", "cppcheck": "cppcheck/cppcheck.py",
           "coccicheck": "coccinelle/coccicheck.py", "scs_lint": "scs_lint/run_scs_lint.sh"}


def driver_command(tool):
    path = str(ROOT / "scripts" / DRIVERS[tool])
    if tool == "scs_lint":
        return [path]
    return [sys.executable, "-B", path, *([tool] if tool in {"sparse", "smatch"} else [])]


def probe(command):
    try:
        result = run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     text=True, errors="replace", timeout=15)
        return {"status": result.returncode, "output": result.stdout.strip()}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"status": None, "output": str(error)}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def metadata(tool, environment):
    name = {"coccicheck": "spatch", "scs_lint": "uv"}.get(tool, tool)
    binary = checker_path() if tool == "checkpatch" else Path(shutil.which(name) or name)
    version = probe([str(binary), "--version"])
    provenance = Path("/usr/local/share/scst-ci") / (tool + "-source.txt")
    kernel = Path(environment.get("SCST_LINT_KDIR") or environment.get("KDIR") or
                  f"/lib/modules/{environment.get('KVER') or os.uname().release}/build")
    result = {
        "commit": probe(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "branch": probe(["git", "-C", str(ROOT), "branch", "--show-current"]),
        "worktree": probe(["git", "-C", str(ROOT), "status", "--porcelain"]),
        "kernel": str(kernel.resolve()) if tool != "scs_lint" else None,
        "kernel_config_sha256": digest(kernel / ".config") if tool != "scs_lint" else None,
        "tool": str(binary), "tool_sha256": digest(binary), "version": version,
        "source_provenance": provenance.read_text() if provenance.exists() else "unavailable",
        "configuration": build_configuration(environment) if tool in
                         {"sparse", "smatch", "cppcheck"} else {},
        "environment_tools": {name: probe([name, "--version"])
                              for name in ("make", "gcc", "ld", "pahole", "python3")
                              if tool in {"sparse", "smatch", "cppcheck", "coccicheck"}},
    }
    if not provenance.exists() and binary.is_file() and shutil.which("rpm"):
        package = probe(["rpm", "-qf", str(binary.resolve())])
        if package["status"] == 0:
            result["source_provenance"] = "Package: " + package["output"]
    if tool == "checkpatch":
        result["data_sha256"] = {name: digest(binary.with_name(name))
                                 for name in ("spelling.txt", "const_structs.checkpatch")}
    if tool == "scs_lint":
        driver = ROOT / "scripts/scs_lint/scs_lint.py"
        result.update(driver=str(driver), driver_sha256=digest(driver),
                      source_provenance="SCST checkout; revision recorded above")
    return result


def build_configuration(environment):
    """Describe defaults without pretending that an unset variable is a value."""
    kunit_default = (f"{environment['CONFIG_SCST_KUNIT_TEST']} (CONFIG_SCST_KUNIT_TEST)"
                     if environment.get("CONFIG_SCST_KUNIT_TEST") else "n (default)")
    defaults = {"KUNIT_TEST": kunit_default, "KUNIT_LABEL": "ALL (default)",
                "QLA_32GBIT": "yes (default: newer QLogic tree)",
                "ARCH": f"Kbuild default (host machine: {os.uname().machine})",
                "CROSS_COMPILE": "not set; use the Kbuild toolchain default", "WERROR": "n (default)"}
    return {key: environment.get(key) or value for key, value in defaults.items()}


def policy_snapshot(tool):
    return {"policy": tool, "policy_file": f"scripts/policy/{tool}.json",
            "configured_policy": load_policy(tool), "effective_source_policy": source_policy(tool),
            "inline_exceptions": inline_inventory(ROOT, tool), "models": integration(ROOT, tool)}


def policy_lines(policy):
    from collections import Counter

    scope = policy["effective_source_policy"]
    configured = policy["configured_policy"]
    lines = [f"Included roots: {', '.join(scope['source_roots'])}",
             f"File types: {', '.join(scope['source_suffixes'])}"]
    lines.extend(f"Excluded directory: {row['path']}: {row['reason']}"
                 for row in scope["exclude_directories"])
    lines.extend(f"Excluded filename suffix: {row['suffix']}: {row['reason']}"
                 for row in scope["exclude_suffixes"])
    lines.extend(scope["notes"])
    entries = policy["inline_exceptions"]
    lines.append(f"Inline exception declarations: {len(entries)} (not matched diagnostics)")
    lines.extend(f"  {count} [{rule}] ({scope})" for (rule, scope), count in sorted(
        Counter((entry["rule"], entry["scope"]) for entry in entries).items()))
    for kind in ("source_exceptions", "kernel_exceptions"):
        for row in configured.get(kind, []):
            location = row.get("file", row.get("header", ""))
            lines.append(f"Exception: {location} {row.get('function', '')}: "
                         f"{row['message']} — {row['reason']}")
    if "disabled_checks" in configured:
        lines.append("Globally disabled Checkpatch categories: " +
                     (", ".join(row["id"] for row in configured["disabled_checks"]) or "none"))
        lines.append(f"Reviewed layouts: {len(configured['line_layouts'])} lines; "
                     f"{len(configured['macro_body_layouts'])} macros")
        versions = configured["version_comparisons"]
        lines.append("Version comparisons in #if/#elif: " + ", ".join(
            [item["name"] for item in versions["code_macros"]] + versions["integer_macros"]))
        lines.extend(f"Logging strings ({item['file_glob']}): {', '.join(item['names'])}"
                     for item in configured["logging_calls"])
    for row in configured.get("omitted_system_headers", []):
        lines.append(f"Omitted header bodies ({', '.join(row['profiles'])}): "
                     f"{len(row['headers'])} exact header names; {row['reason']}")
    for model in policy["models"]:
        lines.append(f"Model: {model['path']}: {model['reason']}")
    if "macro_definition_errors" in configured:
        setting = configured["macro_definition_errors"]
        lines.append(f"Non-blocking macro definition errors: {setting['enabled']}; {setting['reason']}")
    lines.extend(configured.get("notes", []))
    return lines


def print_metadata(tool, data, policy):
    def value(row):
        return row["output"] if row["status"] == 0 else "unavailable"

    branch = value(data["branch"]) or "detached HEAD"
    state = data["worktree"]
    if state["status"] != 0:
        worktree = "unknown (git status failed)"
    else:
        rows = state["output"].splitlines()
        untracked = sum(row.startswith("?? ") for row in rows)
        worktree = (f"modified ({len(rows) - untracked} tracked; {untracked} untracked entries)"
                    if rows else "clean")
    print("SCST info (analyzed checkout):")
    print(f"  Commit: {value(data['commit'])}\n  Branch: {branch}; worktree: {worktree}")
    if data['kernel']:
        print(f"  Kernel build tree: {data['kernel']}")
    print(f"\nTool: {data.get('driver', data['tool'])}")
    version = value(data["version"])
    if tool == "checkpatch":
        version = next((line for line in version.splitlines() if line.startswith("Version:")),
                       "Version: unavailable (no Version field)").removeprefix("Version:").strip()
    if data.get("driver"):
        print(f"Driver SHA256: {data['driver_sha256']}")
        print(f"Runtime launcher: {data['tool']}; {version}")
        print(f"Launcher SHA256: {data['tool_sha256'] or 'unavailable'}")
    else:
        print(f"Version: {version.splitlines()[0] if version else 'unavailable'}")
        print(f"SHA256: {data['tool_sha256'] or 'unavailable'}")
    print(f"Source: {data['source_provenance'].strip()}")
    if data["configuration"]:
        print("\nBuild configuration:")
        for key, item in data["configuration"].items():
            print(f"  {key}={item}")
    if data["environment_tools"]:
        print("\nEnvironment:")
        for name, row in data["environment_tools"].items():
            text = value(row).splitlines()
            print(f"  {name}: {text[0] if text else 'unavailable'}")
    print("\nAnalysis mode: full configured scope")
    print(f"Policy: {policy['policy_file']}")
    print(report_section("Configured policy and models", policy_lines(policy), collapsed=True), flush=True)


def current_report(path, tool, identity):
    if not path.is_file():
        raise ValueError("analyzer did not publish a result")
    report = json.loads(path.read_text())
    if not isinstance(report, dict) or report.get("run_id") != identity or report.get("tool") != tool:
        raise ValueError("analyzer result does not belong to this invocation")
    return report


def print_reports(tool, cache, report):
    print_phase(tool, "Reports")
    for suffix, label in (("summary.log", "Summary"), ("summary.md", "Markdown summary"),
                          ("json", "Machine report"),
                          ("log", "Full native log"), ("execution.log", "Execution log"),
                          ("environment.json", "Tool and checkout"), ("policy.json", "Policy inventory"),
                          ("run.json", "Run status")):
        path = cache / f"{tool}.{suffix}"
        # A missing/foreign native report must not advertise stale evidence.
        if path.is_file() and (report or suffix not in {"json", "log"}):
            print(f"  {label}: {path}")
    if report.get("records_directory"):
        print(f"  Per-invocation evidence: {report['records_directory']}")


def progress_label(tool, path, identity):
    try:
        record = json.loads(path.read_text())
        if (record.get("run_id") == identity and type(record.get("current")) is int and
                type(record.get("total")) is int and 0 < record["current"] <= record["total"] and
                isinstance(record.get("rule"), str) and
                re.fullmatch(r"[A-Za-z0-9_.-]+\.cocci", record["rule"])):
            return (f"{tool}: analysis (current rule {record['current']}/{record['total']} "
                    f"{record['rule']})")
    except (OSError, ValueError, AttributeError):
        pass
    return f"{tool}: analysis"


def execute(tool):
    cache = ROOT / ".cache/lint"
    cache.mkdir(parents=True, exist_ok=True)
    with report_lock(ROOT, tool) as lock_fd:
        identity = os.environ.get("SCST_LINT_RUN_ID") or str(uuid.uuid4())
        environment = dict(os.environ, SCST_LINT_RUN_ID=identity, LINT_DEFER_REPORTS="1",
                           LINT_REPORT_LOCK_TOOL=tool, LINT_REPORT_LOCK_FD=str(lock_fd))
        command = driver_command(tool)
        manifest = cache / f"{tool}.run.json"
        execution = cache / f"{tool}.execution.log"
        summary = cache / f"{tool}.summary.log"
        markdown = cache / f"{tool}.summary.md"
        progress = cache / f"{tool}.progress.json"
        environment["SCST_LINT_PROGRESS"] = str(progress)
        progress.unlink(missing_ok=True)
        status, report, text, markdown_text, result_started = 2, {}, "", "", False
        state = {"tool": tool, "run_id": identity, "command": command, "state": "started", "status": 2}
        manifest.write_text(json.dumps(state, indent=2) + "\n")
        execution.write_bytes(b"")
        summary.write_text("")
        markdown.write_text("")
        # Do not retain previous metadata if this preparation fails.
        for suffix in ("environment.json", "policy.json"):
            (cache / f"{tool}.{suffix}").unlink(missing_ok=True)
        print_phase(tool, "Start")
        try:
            data = metadata(tool, environment)
            (cache / f"{tool}.environment.json").write_text(json.dumps(data, indent=2) + "\n")
            policy = policy_snapshot(tool)
            (cache / f"{tool}.policy.json").write_text(json.dumps(policy, indent=2) + "\n")
            print_metadata(tool, data, policy)
            print_phase(tool, "Run")
            print(f"Analysis in progress; full output: {execution}\n", flush=True)
            with execution.open("wb") as output:
                # Let the driver finish its native-process escalation and
                # save partial evidence before escalating against the driver.
                status = run(command, env=environment, cwd=ROOT, stdout=output,
                             stderr=subprocess.STDOUT, progress_stream=sys.stdout,
                             pass_fds=(lock_fd,), cancel_timeout=10,
                             progress=lambda: progress_label(tool, progress, identity)).returncode
            if status >= 128:
                raise Interrupted(status - 128)
            report = current_report(cache / f"{tool}.json", tool, identity)
            if not (cache / f"{tool}.log").is_file():
                raise ValueError("analyzer did not retain its native log")
            if (type(report.get("exit_code")) is not int or report["exit_code"] != status or
                    report.get("outcome") not in {0: {"clean", "skipped"}, 1: {"findings"},
                                                  2: {"incomplete"}}.get(status, set())):
                raise ValueError("analyzer exit status disagrees with its result")
            print_phase(tool, "Result")
            result_started = True
            text = render(report, cache / f"{tool}.log", include_reports=False)
            markdown_text = render(report, cache / f"{tool}.log", include_reports=False, markdown=True)
            print(text, end="", flush=True)
            state["state"] = report.get("outcome", "incomplete")
        except (Interrupted, KeyboardInterrupt) as error:
            status = 128 + error.signum if isinstance(error, Interrupted) else 130
            text = f"{LABELS[tool]}: FAIL; analysis interrupted (exit {status})\n"
            state["state"] = "interrupted"
            markdown_text = ""
            if not result_started:
                print_phase(tool, "Result")
            print(text, end="", flush=True)
        except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
            status = 2
            state.update(state="incomplete", error=str(error))
            markdown_text = ""
            if not result_started:
                print_phase(tool, "Result")
            text = f"{LABELS[tool]}: FAIL; analysis incomplete (exit 2)\nINCOMPLETE: {error}\n"
            tail = execution.read_text(errors="replace").splitlines()[-24:]
            if tail:
                text += report_section("Execution failure context", tail)
            print(text, end="", flush=True)
        finally:
            state["status"] = status
            manifest.write_text(json.dumps(state, indent=2) + "\n")
            summary.write_text(text)
            markdown.write_text(markdown_text or markdown_block(text))
            # The native CI wrapper publishes only after its stronger coverage gate.
            if os.environ.get("GITHUB_STEP_SUMMARY") and not os.environ.get("SCST_LINT_CI_WRAPPER"):
                with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
                    stream.write(markdown.read_text())
            print_reports(tool, cache, report)
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=tuple(DRIVERS))
    args = parser.parse_args()
    return execute(args.tool)


if __name__ == "__main__":
    sys.exit(entrypoint(main))
