"""Pytest bootstrap: make the project importable without installation.

Pytest imports this before collecting tests, so test modules can simply
``from hashcracker...`` whether or not the package is pip-installed.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
