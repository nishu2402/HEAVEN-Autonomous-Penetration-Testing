"""
HEAVEN — Deterministic seeding for reproducible scans.

A pen-test that can't be reproduced isn't a pen-test, it's an anecdote.
The orchestrator's multi-armed bandit, the payload selector, and any
timing-based detection thresholds all touch random state. Without a
central seed they drift run-to-run and the same scan against the same
target yields different findings.

This module gives every random consumer a single place to pull from.
When `HEAVEN_SEED` is set (or `set_seed(N)` is called), every consumer
that uses `get_random()` / `get_numpy_rng()` gets a deterministic
stream. Otherwise it falls back to fresh entropy each run, preserving
existing behaviour.

Consumers:
  - heaven.ml.ai_brain.ScanStrategyOptimizer  (epsilon-greedy / UCB)
  - heaven.recon.evasion_engine               (User-Agent rotation)
  - any future module that needs reproducibility
"""

from __future__ import annotations

import os
import random
from typing import Any, Optional


_seed: Optional[int] = None
_random: Optional[random.Random] = None
_numpy_rng: Any = None  # numpy.random.Generator | None


def _load_seed_from_env() -> Optional[int]:
    raw = os.environ.get("HEAVEN_SEED", "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def set_seed(seed: Optional[int]) -> None:
    """Set (or clear) the project-wide seed. Pass None to revert to entropy."""
    global _seed, _random, _numpy_rng
    _seed = seed
    if seed is None:
        _random = None
        _numpy_rng = None
        os.environ.pop("HEAVEN_SEED", None)
        return
    _random = random.Random(seed)  # nosec B311 -- deterministic seedable repro RNG
    try:
        import numpy as np
        _numpy_rng = np.random.default_rng(seed)
    except ImportError:
        _numpy_rng = None
    os.environ["HEAVEN_SEED"] = str(seed)


def current_seed() -> Optional[int]:
    """Return the active seed, or None when running with fresh entropy."""
    global _seed
    if _seed is None:
        env_seed = _load_seed_from_env()
        if env_seed is not None:
            set_seed(env_seed)
    return _seed


def get_random() -> random.Random:
    """Return the project Random instance. Always seeded if a seed is active."""
    global _random
    if _random is None:
        seed = current_seed()
        _random = random.Random(seed) if seed is not None else random.Random()  # nosec B311
    return _random


def get_numpy_rng() -> Any:
    """Return numpy Generator if numpy installed, else None."""
    global _numpy_rng
    if _numpy_rng is None and current_seed() is not None:
        try:
            import numpy as np
            _numpy_rng = np.random.default_rng(current_seed())
        except ImportError:
            return None
    return _numpy_rng


def reset() -> None:
    """Test helper — clear all cached state."""
    global _seed, _random, _numpy_rng
    _seed = None
    _random = None
    _numpy_rng = None
    os.environ.pop("HEAVEN_SEED", None)
