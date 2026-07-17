"""Assemble the explorer entry document from its ordered source fragments."""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parent
MANIFEST_NAME = "index.parts"


def source_parts(source_root: Path = SOURCE_ROOT) -> list[Path]:
    """Return validated source paths in document order."""
    manifest = source_root / MANIFEST_NAME
    entries = [
        line.strip()
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not entries:
        raise ValueError(f"{manifest} contains no explorer source parts")

    root = source_root.resolve()
    seen: set[Path] = set()
    paths: list[Path] = []
    for entry in entries:
        relative = Path(entry)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"unsafe explorer source path: {entry}")
        path = (root / relative).resolve()
        if root not in path.parents:
            raise ValueError(f"explorer source escapes source root: {entry}")
        if path in seen:
            raise ValueError(f"duplicate explorer source path: {entry}")
        if not path.is_file():
            raise FileNotFoundError(f"explorer source part not found: {entry}")
        if path.stat().st_size == 0:
            raise ValueError(f"explorer source part is empty: {entry}")
        seen.add(path)
        paths.append(path)
    return paths


def assemble_index(source_root: Path = SOURCE_ROOT) -> bytes:
    """Join source bytes without rewriting whitespace or line endings."""
    return b"".join(path.read_bytes() for path in source_parts(source_root))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Assemble CoinCync explorer index.html from index.parts."
    )
    parser.add_argument("output", type=Path, help="destination index.html or '-' for stdout")
    args = parser.parse_args()

    assembled = assemble_index()
    if str(args.output) == "-":
        import sys

        sys.stdout.buffer.write(assembled)
        return

    destination = args.output.resolve()
    if destination == SOURCE_ROOT or SOURCE_ROOT in destination.parents:
        raise ValueError("refusing to write assembled output inside explorer sources")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(assembled)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
