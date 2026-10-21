"""Shared pytest configuration and session-scoped fixtures.

Only pytest-specific items live here (fixtures, hooks).
Plain constants belong in tests/helpers.py so they can be imported at
module collection time without depending on pytest fixture machinery.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# tests/fixtures/ — committed to git; built once with convert_data.py --fixture
FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixture_dir() -> Path:
    """Return the path to tests/fixtures/. Skip the whole session if absent."""
    if not FIXTURE_DIR.exists():
        pytest.skip("tests/fixtures/ not found. Run: python scripts/convert_data.py --fixture")
    return FIXTURE_DIR
