import sys
from pathlib import Path

# Allow `pytest` to discover the package even when it's not installed
# (mirrors N2-NG_v2/tests/conftest.py's pattern). No n2ng2 path needed
# here anymore — atwa is fully self-contained as of 2026-08-25 (the
# whole attack/crypto engine was physically copied in, not imported).
_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
