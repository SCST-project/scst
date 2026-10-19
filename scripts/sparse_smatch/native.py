"""Native checker options; never modify installed tools or Smatch models."""

import os
from pathlib import Path
import shutil


def checker_command(tool):
    if tool not in ("sparse", "smatch"):
        raise ValueError(f"unsupported checker: {tool}")
    executable = shutil.which(tool)
    if not executable:
        raise ValueError(f"{tool} is not installed")
    options = [executable]
    if tool == "smatch":
        binary = Path(executable).resolve()
        explicit = os.environ.get("SMATCH_DATA_DIR")
        candidates = ([Path(explicit)] if explicit else [
            binary.parent / "smatch_data",
            binary.parent.parent / "share/smatch/smatch_data",
            Path.home() / "share/smatch/smatch_data",
        ])
        data = next((p.resolve() for p in candidates
                     if (p / "kernel.unreachable.turn_off").is_file()), None)
        if data is None:
            raise ValueError("Smatch data not found; install matching smatch_data or set SMATCH_DATA_DIR")
        options += ["-p=kernel", "--data=" + str(data)]
    return options
