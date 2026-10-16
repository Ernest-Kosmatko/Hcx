"""hcx - orchestration layer around hashcat.

Wraps the stock hashcat binary without altering or hiding any of its
features. Every original flag is passed straight through; hcx only adds
convenience on top: job management, reporting, attack planning, hash
identification and tuning helpers.
"""

__version__ = "0.1.0"
