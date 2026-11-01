import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SAMPLES = os.path.join(ROOT, "samples")


@pytest.fixture(scope="session")
def run():
    """Analyse a committed sample (in-process) and cache the result."""
    from engine.analyze import analyze

    cache = {}

    def _run(name):
        if name not in cache:
            cache[name] = analyze(os.path.join(SAMPLES, name))
        return cache[name]

    return _run


def kinds(result, verdict=None):
    return [f.kind for f in result.findings if verdict is None or f.verdict == verdict]
