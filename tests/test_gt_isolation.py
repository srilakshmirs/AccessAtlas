"""GT isolation enforcement test.

This test scans every Python source file under accessatlas/ EXCEPT the
evaluation subpackage, and fails if it finds any reference to the four
ground-truth sheet names.

WHY: The GT_ sheets are evaluation-only data. Leaking them into detection or
resolution code would make accuracy metrics meaningless (the model would be
tuned on its own test labels).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

# The four GT sheet names that must never appear outside evaluation/.
GT_NAMES = {
    "GT_Labels",
    "GT_EffectivePrivilege",
    "GT_IdentityLinks",
    "GT_InjectedEvents",
}

# Root of the Python package relative to the repo root.
PACKAGE_ROOT = Path(__file__).parent.parent / "accessatlas"

# The evaluation subpackage is the only place allowed to reference GT_ data.
EVALUATION_DIR = PACKAGE_ROOT / "evaluation"


def _python_files_outside_evaluation() -> list[Path]:
    """Return all .py files under accessatlas/ that are NOT inside evaluation/."""
    return [p for p in PACKAGE_ROOT.rglob("*.py") if not p.is_relative_to(EVALUATION_DIR)]


@pytest.mark.parametrize("py_file", _python_files_outside_evaluation())
def test_no_gt_reference_outside_evaluation(py_file: Path) -> None:
    """No non-evaluation source file may mention a GT_ sheet name as a string literal."""
    source = py_file.read_text(encoding="utf-8")

    # Check string literals via AST so we don't false-positive on comments
    # that merely explain what GT_ sheets ARE (like this file).
    try:
        tree = ast.parse(source)
    except SyntaxError:
        pytest.skip(f"Could not parse {py_file} — skipping AST check")
        return

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for gt_name in GT_NAMES:
                assert gt_name not in node.value, (
                    f"{py_file.relative_to(PACKAGE_ROOT.parent)} "
                    f"contains GT name '{gt_name}' in a string literal "
                    f"(line {node.lineno}). "
                    "GT_ sheets are evaluation-only — move this to accessatlas/evaluation/."
                )

    # Also catch bare name usage (e.g. someone writes GT_Labels without quotes)
    # via regex on the raw source, excluding import lines that re-export names.
    for gt_name in GT_NAMES:
        matches = list(re.finditer(rf"\b{re.escape(gt_name)}\b", source))
        # Allow the name to appear in comments that explain the rule.
        non_comment_matches = [m for m in matches if not _is_in_comment(source, m.start())]
        assert not non_comment_matches, (
            f"{py_file.relative_to(PACKAGE_ROOT.parent)} "
            f"references '{gt_name}' (line(s): "
            f"{[_line_no(source, m.start()) for m in non_comment_matches]}). "
            "GT_ sheets are evaluation-only."
        )


def _is_in_comment(source: str, pos: int) -> bool:
    """Return True if the character at `pos` is inside a # comment on its line."""
    line_start = source.rfind("\n", 0, pos) + 1
    line = source[line_start:pos]
    return "#" in line


def _line_no(source: str, pos: int) -> int:
    """Return the 1-based line number for a character position."""
    return source[:pos].count("\n") + 1
