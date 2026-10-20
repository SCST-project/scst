#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

if ! command -v uv >/dev/null; then
    echo "scs_lint: uv is required to run the pinned Python dependencies" >&2
    exit 2
fi

exec uv run --no-project "$HERE/scs_lint.py" "$@"
