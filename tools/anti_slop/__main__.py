"""Run the vendored anti-slop linter: ``python tools/anti_slop``.

Executing this directory places it on ``sys.path``, so the sibling ``anti_slop``
package imports as a top-level module without being installed. Written by the
install-anti-slop-py skill; the package next to it is an unmodified copy.
"""

import sys

if sys.version_info < (3, 12):
    running = ".".join(str(part) for part in sys.version_info[:3])
    raise SystemExit(
        "anti-slop needs Python 3.12+, but this is " + running + " ("
        + sys.executable + "). Point the runner at a newer interpreter."
    )

from anti_slop.__main__ import main  # noqa: E402

raise SystemExit(main())
