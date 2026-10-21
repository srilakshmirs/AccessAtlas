"""Tests for data cleaning helpers (accessatlas.ingestion.cleaning)."""

from __future__ import annotations

import pandas as pd

from accessatlas.ingestion.cleaning import coerce_bool, coerce_date


class TestCoerceDate:
    def test_parses_valid_date(self) -> None:
        s = pd.Series(["2026-01-15", "2025-06-30"])
        result = coerce_date(s)
        assert pd.api.types.is_datetime64_any_dtype(result)
        assert result[0] == pd.Timestamp("2026-01-15")

    def test_na_strings_become_nat(self) -> None:
        """'n/a', 'N/A', '', '-' must all become NaT."""
        s = pd.Series(["n/a", "N/A", "na", "", "-", "none", "null"])
        result = coerce_date(s)
        assert result.isna().all(), f"Expected all NaT, got: {result.tolist()}"

    def test_mixed_valid_and_na(self) -> None:
        s = pd.Series(["2026-05-01", "n/a", "2026-06-15"])
        result = coerce_date(s)
        assert result[0] == pd.Timestamp("2026-05-01")
        assert pd.isna(result[1])
        assert result[2] == pd.Timestamp("2026-06-15")

    def test_nat_passthrough(self) -> None:
        """NaT values already in the series must survive unchanged."""
        s = pd.Series([pd.NaT, pd.Timestamp("2026-01-01")])
        result = coerce_date(s)
        assert pd.isna(result[0])


class TestCoerceBool:
    def test_string_true_false(self) -> None:
        s = pd.Series(["true", "True", "TRUE", "false", "False", "FALSE"])
        result = coerce_bool(s)
        assert list(result[:3]) == [True, True, True]
        assert list(result[3:]) == [False, False, False]

    def test_integer_0_1(self) -> None:
        s = pd.Series([0, 1, 0, 1], dtype=int)
        result = coerce_bool(s)
        assert list(result) == [False, True, False, True]

    def test_float_with_nan(self) -> None:
        """0.0/1.0 should become False/True; NaN should become pd.NA."""
        s = pd.Series([1.0, 0.0, float("nan")])
        result = coerce_bool(s)
        assert result[0] is True or result[0] == True  # noqa: E712
        assert result[1] is False or result[1] == False  # noqa: E712
        assert pd.isna(result[2])

    def test_already_bool_passthrough(self) -> None:
        s = pd.Series([True, False, True])
        result = coerce_bool(s)
        # dtype may differ (bool vs boolean) but values must be correct
        assert list(result) == [True, False, True]

    def test_unknown_strings_become_na(self) -> None:
        s = pd.Series(["yes", "no", "maybe"])
        result = coerce_bool(s)
        assert result[0] is True or result[0] == True  # noqa: E712
        assert result[1] is False or result[1] == False  # noqa: E712
        assert pd.isna(result[2])
