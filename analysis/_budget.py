"""Wall-clock budget shared by the long analyses.

tools/suite.py sets RAM_DEADLINE (Unix time) for every job; scripts call
remaining() to size their work and expired() to stop between units, saving
what they have. Without RAM_DEADLINE nothing is limited.
"""
import os
import time

_DEADLINE = float(os.environ.get("RAM_DEADLINE", "0") or 0)


def remaining(default=float("inf")):
    """Seconds left (minus a 20 s margin to write results), or default."""
    if not _DEADLINE:
        return default
    return max(0.0, _DEADLINE - time.time() - 20)


def expired():
    return remaining() <= 0


def cap(seconds):
    """A per-call timeout that never runs past the deadline (>= 1 s)."""
    return max(1, int(min(seconds, remaining())))


_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
_CANON = os.path.join(_ROOT, "results")
_OUT = os.environ.get("RAM_RESULTS") or _CANON


def out(name):
    """Where to write a result: RAM_RESULTS (a suite run's own folder, so a
    short budgeted run never overwrites the canonical long-run results) or
    results/."""
    os.makedirs(_OUT, exist_ok=True)
    return os.path.join(_OUT, name)


def src(name):
    """Where to read an input result: this run's folder if it produced it,
    else the canonical results/."""
    p = os.path.join(_OUT, name)
    return p if os.path.exists(p) else os.path.join(_CANON, name)
