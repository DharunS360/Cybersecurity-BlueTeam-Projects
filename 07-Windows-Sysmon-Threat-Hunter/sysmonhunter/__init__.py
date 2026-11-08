"""SysmonHunter - Windows Event / Sysmon threat hunting toolkit."""
__version__ = "1.0.0"

from . import rules_extra  # noqa: E402,F401  (registers the extended detection pack)
from . import demo as _demo  # noqa: E402
from . import demo_extra as _demo_extra  # noqa: E402

_base_generate = _demo.generate


def _generate_full():
    return _demo_extra.extend(_base_generate())


_demo.generate = _generate_full