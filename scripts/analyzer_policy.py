"""Load the shared analyzer input policy without invoking an analyzer."""

import json
from functools import lru_cache
from pathlib import Path

POLICY_PATH = Path(__file__).resolve().parent / "policy/common.json"

SCHEMA = {
    "version": int,
    "source_roots": [str],
    "source_suffixes": [str],
    "exclude_directories": [{"path": str, "reason": str}],
    "exclude_suffixes": [{"suffix": str, "reason": str}],
    "notes": [str],
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate policy key: {key}")
        result[key] = value
    return result


def validate(value, schema, location):
    """Reject unknown, missing and mistyped fields, including nested rules."""
    if isinstance(schema, dict):
        if not isinstance(value, dict) or value.keys() != schema.keys():
            raise ValueError(f"{location}: expected fields {', '.join(schema)}")
        for key, child in schema.items():
            validate(value[key], child, f"{location}.{key}")
    elif isinstance(schema, list):
        if not isinstance(value, list):
            raise ValueError(f"{location}: expected a list")
        for index, item in enumerate(value):
            validate(item, schema[0], f"{location}[{index}]")
    elif type(value) is not schema:
        raise ValueError(f"{location}: expected {schema.__name__}")
    elif schema is str and not value.strip():
        raise ValueError(f"{location}: empty value")


def read_policy(path: Path) -> dict:
    policy = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    validate(policy, SCHEMA, str(path))
    if policy["version"] != 1:
        raise ValueError(f"{path}: unsupported policy version")
    for key in ("source_roots", "source_suffixes"):
        if not policy[key] or len(policy[key]) != len(set(policy[key])):
            raise ValueError(f"{path}: {key} must be nonempty and unique")
    if set(policy["source_suffixes"]) - {".c", ".h"}:
        raise ValueError(f"{path}: only C sources and headers are supported")
    for key, field in (("exclude_directories", "path"), ("exclude_suffixes", "suffix")):
        entries = [rule[field] for rule in policy[key]]
        if len(entries) != len(set(entries)):
            raise ValueError(f"{path}: duplicate {key} entry")
    directories = policy["source_roots"] + [r["path"] for r in policy["exclude_directories"]]
    for directory in directories:
        if (directory.startswith("/") or "\\" in directory or
                any(part in {"", ".", ".."} for part in directory.split("/")) or
                any(ord(char) < 32 or ord(char) == 127 for char in directory)):
            raise ValueError(f"{path}: expected a normalized repository-relative path: "
                             f"{directory!r}")
    for rule in policy["exclude_suffixes"]:
        suffix = rule["suffix"]
        if not suffix.startswith(".") or any(char not in ".abcdefghijklmnopqrstuvwxyz"
                                             "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                                             for char in suffix):
            raise ValueError(f"{path}: expected a literal filename suffix: {suffix!r}")
    return policy


@lru_cache(maxsize=1)
def load_policy() -> dict:
    """Read once per process; invalid or missing policy must stop selection."""
    return read_policy(POLICY_PATH)
