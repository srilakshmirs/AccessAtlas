"""Shared helpers used across the accessatlas package."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml


def load_config(config_path: str | Path = "config.yaml") -> dict:
    """Load the YAML config file.

    The path is resolved relative to the repo root (current working directory),
    so callers do not need to know where the file lives.
    """
    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path.resolve()}")
    with config_path.open() as fh:
        return yaml.safe_load(fh)


def setup_logging(level: str = "INFO") -> None:
    """Configure root logger with a consistent format.

    Called once at the entry point (scripts, API startup).
    """
    fmt = "%(asctime)s %(name)-20s %(levelname)-8s %(message)s"
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format=fmt)
