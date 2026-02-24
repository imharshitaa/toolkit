"""
ToolKit - Cloud-based Cybersecurity Products Implementation Solutions

A comprehensive CLI framework for deploying and managing enterprise
cybersecurity tools across SOC, EDR, Network, Application, and Cloud security domains.
"""

__version__ = "1.0.0"
__author__ = "ToolKit Team"
__license__ = "MIT"

from toolkit.core import ToolKitCore
from toolkit.utils import logger

__all__ = ['ToolKitCore', 'logger', '__version__']
