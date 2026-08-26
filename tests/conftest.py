import sys
from pathlib import Path

# Allow `pytest` to discover the package even when it's not installed.
# atwa is fully self-contained — no external package path needed here.
_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
