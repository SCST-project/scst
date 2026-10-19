"""Serialize analyzer builds within one working tree."""

from contextlib import contextmanager
import fcntl


@contextmanager
def build_lock(root):
    path = root / ".cache/lint/kbuild.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield
