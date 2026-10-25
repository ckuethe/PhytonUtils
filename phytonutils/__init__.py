"""Python port of PhytonUtils.

Utilities for devices released by Phyton / Фитон and related companies.
Mirrors the Go package layout (buffer, compression, crc, encryption, firmware,
math, utils).
"""

from . import buffer  # noqa: F401
from . import crc  # noqa: F401
from . import utils  # noqa: F401
from . import math_modular  # noqa: F401
