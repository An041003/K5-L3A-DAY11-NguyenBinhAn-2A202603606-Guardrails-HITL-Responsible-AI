"""Idempotently replace ONLY the starter's CP4 TODO list, preserving its runner.

Usage from root of the forked lab repository:
    python scripts/apply_prompts.py
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "src" / "attacks" / "attacks.py"
IMPORT = "from attacks.lab11_prompts import adversarial_prompts"


def main() -> None:
    if not TARGET.is_file():
        raise SystemExit(
            f"Missing starter file {TARGET}. Extract the overlay INTO your cloned starter."
        )
    source = TARGET.read_text(encoding="utf-8")
    tree = ast.parse(source)
    found = [
        n for n in tree.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "adversarial_prompts" for t in n.targets)
    ]
    if found:
        target = found[0]
        lines = source.splitlines(keepends=True)
        lines[target.lineno - 1 : target.end_lineno] = [IMPORT + "\n"]
        TARGET.write_text("".join(lines), encoding="utf-8")
        print("Applied CP4 prompts to original attack runner (preserved functions).")
    elif IMPORT in source:
        print("CP4 prompts already configured (idempotent).")
    else:
        raise SystemExit("Cannot locate adversarial_prompts in original attacks.py; inspect manually.")


if __name__ == "__main__":
    main()
