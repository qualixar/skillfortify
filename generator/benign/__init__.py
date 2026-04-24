"""Benign category library — populated Stage 6 T3 per LLD-03 §3.

Assembles 5 concrete BenignCategory subclasses into BENIGN_REGISTRY.
"""

from __future__ import annotations

from .api_integration import ApiIntegrationCategory
from .base import BenignCategory
from .data_transformation import DataTransformationCategory
from .development_tooling import DevelopmentToolingCategory
from .file_management import FileManagementCategory
from .system_information import SystemInformationCategory

BENIGN_REGISTRY: dict[str, BenignCategory] = {
    "file_management": FileManagementCategory(),
    "data_transformation": DataTransformationCategory(),
    "api_integration": ApiIntegrationCategory(),
    "development_tooling": DevelopmentToolingCategory(),
    "system_information": SystemInformationCategory(),
}

__all__ = [
    "BenignCategory",
    "BENIGN_REGISTRY",
    "FileManagementCategory",
    "DataTransformationCategory",
    "ApiIntegrationCategory",
    "DevelopmentToolingCategory",
    "SystemInformationCategory",
]
