#!/usr/bin/env python3
"""HashCracker v2.0 - Hash Identification & Cracking Tool"""
import sys
import os

# Allow running from the project directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hashcracker.cli import main
main()
