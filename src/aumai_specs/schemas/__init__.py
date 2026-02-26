"""Schema file references for the aumai_specs package.

All canonical AumAI schema files are stored in this directory.
Access them via the loader module, not directly.
"""
from importlib.resources import files as _resource_files
from pathlib import Path

# Resolve the package-local schema directory path at import time.
# Using importlib.resources makes this work whether the package is installed
# as an editable install, a wheel, or run directly from source.
SCHEMAS_DIR: Path = Path(_resource_files("aumai_specs.schemas").joinpath(""))  # type: ignore[arg-type]

__all__ = ["SCHEMAS_DIR"]
