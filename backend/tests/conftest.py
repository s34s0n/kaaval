# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Make the `app` package importable when running `pytest` from anywhere."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
