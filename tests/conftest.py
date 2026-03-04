import sys
import builtins
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

def ensure(condition: bool, message: object = "expectation failed") -> None:
    if not condition:
        raise AssertionError(message)

builtins.ensure = ensure

